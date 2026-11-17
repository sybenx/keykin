#!/usr/bin/env node
// keykin: this computer as a Keykin device.
//
//   keykin create '<QR text from the box page>' [name]   make an account with the box
//   keykin import '<setup code>' <nsec> [name]           the same, with a key you already have (nsec1… or hex)
//   keykin invite [name]                                 on a NEW device: print its invite
//   keykin add '<invite>'                                on a device in the account: add it, print the join text
//   keykin join '<join text>'                            on the new device: collect its piece
//   keykin status                                        the account and its devices
//   keykin sign '<event json>'                           sign one event
//   keykin block <name> | unblock <name>
//   keykin cycle                                         after a block: drop blocked devices for good
//   keykin serve <port> <address others reach>           stay on and help other devices when the box is off
//   keykin agent <relay url>                             stay on and do what the account page asks: add a device,
//                                                        hand out bunker links, and (after a Yes here) remove blocked devices
//   keykin bunker <relay url>                            sign in to sites (NIP-46)
//   keykin scan '<a site's sign-in code>' [--yes]         sign in to a site that shows a code (the bunker must be running)
//   keykin sites | signout <site or key prefix>          the sites signed in through the bunker
//   keykin login '<text from the box page>'              log a browser in to the box's page
//   keykin nsec                                          form the whole nsec here and print it
//
// State lives in $KEYKIN_HOME/device.json (default ~/.keykin).

import { homedir } from 'node:os';
import { join as pathJoin } from 'node:path';
import * as D from '../src/device.ts';
import { createServer } from 'node:http';
import { load, save, meOf, heldOf, keep, sender } from './store.ts';
import { DeviceHelper } from '../src/helper.ts';
import { newBunker, runBunker, signOut, bunkerUrl, syncGrants } from '../src/nip46.ts';
import { readCode, answerCode, newTicket } from '../src/ticket.ts';
import { getPublicKey } from 'nostr-tools/pure';
import { createInterface } from 'node:readline/promises';
import { nsecEncode, npubEncode, decode as nip19decode } from 'nostr-tools/nip19';
import { hexToBytes } from '../src/bytes.ts';

export async function main(argv: string[], out: (s: string) => void = console.log, home = process.env.KEYKIN_HOME ?? pathJoin(homedir(), '.keykin')) {
  const file = pathJoin(home, 'device.json');
  const [cmd, a, b] = argv;
  const s = load(file, cmd === 'create' ? b : cmd === 'invite' ? a : cmd === 'import' ? argv[3] : undefined);
  const me = meOf(s);
  // The box first; if it cannot be reached, other devices that listen (from the list last seen at the box).
  const box = () => D.withHelpers(sender(s.addr ?? fail('This device does not know a box yet.')),
    (s.list ?? []).filter((m) => m.addr && m.key !== me.key && !m.blocked).map((m) => sender(m.addr!)));
  const remember = async () => { try { s.list = (await D.members(me, sender(s.addr!))).members; save(file, s); } catch { /* box off: keep the old list */ } };
  if (s.held && cmd !== 'status') await remember();
  const byName = async (name: string) => {
    const list = await D.members(me, box());
    return list.members.find((m: any) => m.name === name || m.key.startsWith(name))?.key ?? fail(`No device called "${name}".`);
  };
  switch (cmd) {
    case 'create': {
      if (s.held) fail('This device is already in an account.');
      const qr = D.readQr(a);
      const held = await D.createWithBox(me, qr, sender(qr.addr));
      keep(s, held, qr.addr); save(file, s);
      return out(`Account made. npub (hex): ${held.npub}`);
    }
    case 'import': {
      if (s.held) fail('This device is already in an account.');
      const qr = D.readQr(a);
      const raw = (b ?? '').trim();
      let hex: string;
      try { hex = raw.startsWith('nsec1') ? Buffer.from(nip19decode(raw).data as Uint8Array).toString('hex') : raw; } catch { hex = ''; }
      const held = await D.importWithBox(me, qr, hex, sender(qr.addr));
      keep(s, held, qr.addr); save(file, s);
      return out(`Account brought in. ${npubEncode(held.npub)}`);
    }
    case 'invite': {
      if (s.held) fail('This device is already in an account.');
      save(file, s);
      return out(JSON.stringify({ keykin: 2, invite: { key: me.key, name: me.name, chip: me.chip } }));
    }
    case 'add': {
      const inv = JSON.parse(a)?.invite ?? fail('That is not an invite.');
      const held = heldOf(s);
      await D.addMember(me, held, { key: inv.key, name: String(inv.name), kind: 'device', chip: inv.chip }, box());
      keep(s, held, s.addr!); save(file, s);
      return out(JSON.stringify({ keykin: 2, join: { addr: s.addr, boxKey: held.boxKey, npub: held.npub } }));
    }
    case 'join': {
      if (s.held) fail('This device is already in an account.');
      const j = JSON.parse(a)?.join ?? fail('That is not a join text.');
      const held = await D.join(me, j.boxKey, j.npub, sender(j.addr));
      keep(s, held, j.addr); save(file, s);
      return out(`Joined. npub (hex): ${held.npub}`);
    }
    case 'serve': {
      const held = heldOf(s), port = Number(a);
      if (!port || !b) fail('Give a port and the address other devices reach this computer at, for example: serve 7461 http://100.64.0.5:7461');
      const helper = new DeviceHelper(() => held, me.key);
      const refresh = async () => {
        try {
          // Any catch-up after a cycle happens on a request that needs the current pieces; a message key to itself is the cheapest.
          await D.conversationKey(me, held, held.npub, sender(s.addr!)); keep(s, held, s.addr!);
          helper.list = (await D.members(me, sender(s.addr!))).members; s.list = helper.list as any; save(file, s);
        } catch (e: any) { if (e?.code === 'blocked' || e?.code === 'unknown_member') helper.list = []; else if (!helper.list.length) helper.list = (s.list ?? []) as any; }
      };
      await refresh();
      await D.setAddress(me, b, sender(s.addr!)).catch(() => out('The box is not reachable now; it will learn this address later.'));
      const server = createServer((req, res) => {
        const chunks: Buffer[] = []; let size = 0;
        req.on('data', (c: Buffer) => { size += c.length; if (size > 256 * 1024) req.destroy(); else chunks.push(c); });
        req.on('end', () => {
          let r: any; try { r = helper.handle(JSON.parse(Buffer.concat(chunks).toString('utf8')), Math.floor(Date.now() / 1000)); } catch { r = { error: 'bad_json' }; }
          res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(r));
        });
      });
      await new Promise<void>((ok) => server.listen(port, '0.0.0.0', ok));
      const timer = setInterval(refresh, 30_000);
      out(`Helping other devices at ${b}. Leave this running.`);
      return { close: () => { clearInterval(timer); server.close(); server.closeAllConnections(); }, refresh };
    }
    case 'status': {
      const list = await D.members(me, sender(s.addr ?? fail('This device does not know a box yet.')));
      out(`${npubEncode(list.npub)}`);
      out(`npub (hex): ${list.npub}`);
      for (const m of list.members) out(`  ${m.i}  ${m.name}${m.key === me.key ? ' (this device)' : ''}${m.kind === 'box' ? ' (box)' : ''}${m.blocked ? '  BLOCKED' : ''}`);
      return;
    }
    case 'sign': {
      const held = heldOf(s), e = JSON.parse(a);
      try { return out(JSON.stringify(await D.signEvent(me, held, { pubkey: held.npub, created_at: e.created_at ?? Math.floor(Date.now() / 1000), kind: e.kind ?? 1, tags: e.tags ?? [], content: e.content ?? '' }, box()))); }
      finally { keep(s, held, s.addr!); save(file, s); }
    }
    case 'block': await D.block(me, await byName(a), box()); return out(`${a} is blocked.`);
    case 'unblock': await D.unblock(me, await byName(a), box()); return out(`${a} is unblocked.`);
    case 'cycle': { const held = heldOf(s); await D.cycle(me, held, box()); keep(s, held, s.addr!); save(file, s); return out('Keys cycled. Blocked devices are gone for good.'); }
    case 'nsec': { const held = heldOf(s); const n = await D.formNsec(me, held, box()); keep(s, held, s.addr!); save(file, s); return out(nsecEncode(hexToBytes(n))); }
    case 'login': await D.approveLogin(me, heldOf(s), a, box()); return out('That browser is logged in to the box.');
    case 'scan': {
      const held = heldOf(s);
      if (!s.bunker?.relay) fail('Start the signer first: keykin bunker <relay>. Leave it running, then scan.');
      const params = readCode(a);
      const yes = argv.includes('--yes');
      const ask = async (q: string) => { if (yes) return true; const rl = createInterface({ input: process.stdin, output: process.stdout }); try { return /^y/i.test(await rl.question(`${q} (y/n) `)); } finally { rl.close(); } };
      await answerCode({
        params, viaCamera: false,
        consent: (origin) => ask(`Let ${origin ?? 'that site'} sign as you? It gets access of its own, which you remove with "keykin signout".`),
        mint: (origin) => {
          const fresh = load(file); const bunker = fresh.bunker!;
          const t = newTicket(held.npub, getPublicKey(hexToBytes(bunker.sk)), [bunker.relay!]);
          (bunker.tickets ??= []).push({ t: t.t, expires: t.expires, ...(origin ? { origin } : {}) });
          save(file, fresh);
          return t;
        },
        sameDigits: (digits) => { out(`Digits: ${digits}`); return ask(`Does the site show ${digits}?`); },
      });
      return out(`${params.origin ?? 'That site'} can now sign as you.`);
    }
    case 'sites': { const cs = s.bunker?.clients ?? []; if (!cs.length) return out('No site is signed in.'); for (const c of cs) out(`  ${c}${s.bunker?.origins?.[c] ? `  ${s.bunker.origins[c]}` : ''}`); return; }
    case 'signout': {
      if (!s.bunker || !a) fail('Give the start of a site key from "keykin sites".');
      const gone = signOut(s.bunker!, a); save(file, s);
      return out(gone.length ? `Signed out ${gone.length} site${gone.length > 1 ? 's' : ''}. The bunker link has changed.` : 'No site matches that.');
    }
    case 'agent': {
      if (!a) fail('Give a relay address, for example wss://relay.example.com');
      const held = heldOf(s);
      if (!s.bunker) { s.bunker = newBunker(); save(file, s); }
      const keepAll = () => { keep(s, held, s.addr!); save(file, s); };
      const send = box();
      const run = await runBunker({ bunker: s.bunker, me, held, send, relay: a, onChange: () => { keepAll(); syncGrants(s.bunker!, me, held, send).then(keepAll, () => {}); },
        before: () => { const fresh = load(file).bunker; if (fresh) { s.bunker!.clients = fresh.clients; s.bunker!.secret = fresh.secret; } }, log: out });
      // Hard-to-undo requests ask here. With nobody at the keyboard the answer is No.
      const tap = async (text: string) => {
        if (!process.stdin.isTTY) { out(`Asked: ${text} Nobody is here to answer, so: No.`); return false; }
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        try { return /^y(es)?$/i.test((await rl.question(`${text} [y/N] `)).trim()); } finally { rl.close(); }
      };
      const tick = async () => {
        try {
          for (const did of await D.answerNotes(me, held, send, { addr: s.addr!, tap, bunker: async () => bunkerUrl(s.bunker!, a) })) out(`agent: ${did}`);
          if (await syncGrants(s.bunker!, me, held, send)) out('agent: a sign-in was revoked at the box');
          keepAll();
        } catch (e: any) { if (e?.code === 'blocked' || e?.code === 'unknown_member') out(`agent: this device is ${e.code === 'blocked' ? 'blocked' : 'no longer in the account'}`); }
      };
      await tick();
      const timer = setInterval(tick, 3000);
      out(`Doing what the account page asks. Leave this running.`);
      return { close: () => { clearInterval(timer); run.close(); }, tick };
    }
    case 'bunker': {
      if (!a) fail('Give a relay address, for example wss://relay.example.com');
      const held = heldOf(s);
      if (!s.bunker) { s.bunker = newBunker(); save(file, s); }
      const run = await runBunker({ bunker: s.bunker, me, held, send: box(), relay: a, onChange: () => { keep(s, held, s.addr!); save(file, s); },
        before: () => { const fresh = load(file).bunker; if (fresh) Object.assign(s.bunker!, { clients: fresh.clients, secret: fresh.secret, tickets: fresh.tickets, origins: fresh.origins }); }, log: out });
      out(`Paste this into a site's "remote signer" or "bunker" sign-in:\n${run.url}`);
      return run;
    }
    default: out('Commands: create, import, invite, add, join, status, sign, block, unblock, cycle, serve, bunker, scan, sites, signout, login, nsec'); return;
  }
}
function fail(msg: string): never { throw new Error(msg); }

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((e) => { console.error(String(e?.message ?? e)); process.exit(1); });
}
