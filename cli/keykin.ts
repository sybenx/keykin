#!/usr/bin/env node
// keykin: this computer as a Keykin device.
//
//   keykin create '<QR text from the box page>' [name]   make an account with the box
//   keykin invite [name]                                 on a NEW device: print its invite
//   keykin add '<invite>'                                on a device in the account: add it, print the join text
//   keykin join '<join text>'                            on the new device: collect its piece
//   keykin status                                        the account and its devices
//   keykin sign '<event json>'                           sign one event
//   keykin block <name> | unblock <name>
//   keykin cycle                                         after a block: drop blocked devices for good
//   keykin bunker <relay url>                            sign in to sites (NIP-46)
//   keykin nsec                                          form the whole nsec here and print it
//
// State lives in $KEYKIN_HOME/device.json (default ~/.keykin).

import { homedir } from 'node:os';
import { join as pathJoin } from 'node:path';
import * as D from '../src/device.ts';
import { load, save, meOf, heldOf, keep, sender } from './store.ts';
import { newBunker, runBunker } from '../src/nip46.ts';

export async function main(argv: string[], out: (s: string) => void = console.log, home = process.env.KEYKIN_HOME ?? pathJoin(homedir(), '.keykin')) {
  const file = pathJoin(home, 'device.json');
  const [cmd, a, b] = argv;
  const s = load(file, cmd === 'create' ? b : cmd === 'invite' ? a : undefined);
  const me = meOf(s);
  const box = () => sender(s.addr ?? fail('This device does not know a box yet.'));
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
    case 'status': {
      const list = await D.members(me, box());
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
    case 'nsec': { const held = heldOf(s); const n = await D.formNsec(me, held, box()); keep(s, held, s.addr!); save(file, s); return out(n); }
    case 'bunker': {
      if (!a) fail('Give a relay address, for example wss://relay.example.com');
      const held = heldOf(s);
      if (!s.bunker) { s.bunker = newBunker(); save(file, s); }
      const run = await runBunker({ bunker: s.bunker, me, held, send: box(), relay: a, onChange: () => { keep(s, held, s.addr!); save(file, s); }, log: out });
      out(`Paste this into a site's "remote signer" or "bunker" sign-in:\n${run.url}`);
      return run;
    }
    default: out('Commands: create, invite, add, join, status, sign, block, unblock, cycle, bunker, nsec'); return;
  }
}
function fail(msg: string): never { throw new Error(msg); }

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((e) => { console.error(String(e?.message ?? e)); process.exit(1); });
}
