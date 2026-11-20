// Signing in to a site by scanning its code (QRST signer-ticket), end to end over a local relay:
// a site shows a code, a command-line device answers it, the site redeems the ticket and signs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { verifyEvent, generateSecretKey } from 'nostr-tools/pure';
import { BunkerSigner } from 'nostr-tools/nip46';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';
import { startSignIn, answerCode, readCode, signerTicket, newTicket, type Ticket, type SignInView } from '../src/ticket.ts';
import { load, save } from '../cli/store.ts';

// QRST's own test relay: it passes the loopback check QRST runs on a relay before using it.
const relayTool = process.env.QRST_REPO ? join(process.env.QRST_REPO, 'tools/test-relay.mjs') : join(homedir(), 'qr-secret-transfer/tools/test-relay.mjs');
const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
const closeBox = (b: any) => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
async function cli(home: string, ...argv: string[]) { if (argv[0] === 'create') argv.push('--username', 'aaron', '--password', 'long enough pw'); const lines: string[] = []; const r = await main(argv, (s) => lines.push(s), home); return { text: lines.join('\n'), run: r as any }; }
const waitFor = async <T>(get: () => T | undefined, ms = 15000): Promise<T> => { const end = Date.now() + ms; for (;;) { const v = get(); if (v !== undefined) return v; if (Date.now() > end) throw new Error('timed out waiting'); await new Promise((r) => setTimeout(r, 50)); } };

test('the ticket format: what a site accepts and what it refuses', () => {
  const t = newTicket('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example']);
  const ok = signerTicket.check(signerTicket.encode(t));
  assert.ok(ok.ok); assert.deepEqual((ok as any).value, t);
  assert.match(signerTicket.render(t), /Sign in as aaaaaaaa…, through your signer bbbbbbbb… on relay\.example\?/);
  const bad = (o: object) => signerTicket.check(Buffer.from(JSON.stringify(o)).toString('base64')).ok;
  assert.equal(bad({ ...t, extra: 1 }), false);                              // exactly six members
  assert.equal(bad({ ...t, v: 2 }), false);
  assert.equal(bad({ ...t, t: 'short' }), false);
  assert.equal(bad({ ...t, relays: ['ws://relay.example'] }), false);        // wss only, off this machine
  assert.equal(bad({ ...t, relays: [] }), false);
  assert.equal(bad({ ...t, expires: Math.floor(Date.now() / 1000) - 1 }), false);
  assert.equal(signerTicket.check('not base64!').ok, false);
});

test('a site signs in by a scanned code', { skip: !existsSync(relayTool) && 'the qr-secret-transfer repo is not beside this one', timeout: 60_000 }, async () => {
  const testRelay = await (await import(relayTool)).startRelay({});
  const relay: string = testRelay.url;
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  let bunker: any; const signers: BunkerSigner[] = [];
  try {
    const home = tmp('kk-mac-');
    const npub = /([0-9a-f]{64})/.exec((await cli(home, 'create', b.qr()!, 'MacBook')).text)![1];
    bunker = (await cli(home, 'bunker', relay)).run;

    // The site's half: show a code, take the ticket, ask, redeem it as a NIP-46 connect secret.
    const site = (origin: string) => {
      let view: SignInView = { state: 'starting' }; let asked = ''; let signer: BunkerSigner | undefined;
      const run = startSignIn({
        relays: [relay], baseUrl: `${origin}/`, origin, onView: (v) => { view = v; },
        confirm: async (q) => { asked = q; return true; },
        redeem: async (t: Ticket) => {
          signer = BunkerSigner.fromBunker(generateSecretKey(), { pubkey: t.signer, relays: t.relays, secret: t.t }); signers.push(signer);
          await signer.connect();
          assert.equal(await signer.getPublicKey(), t.pubkey);
        },
      });
      run.done.catch(() => {});
      return { run, view: () => view, asked: () => asked, signer: () => signer! };
    };

    // 1. A pasted code: the signer shows five digits and they must be the ones on the site.
    const shop = site('https://shop.example');
    const uri = await waitFor(() => shop.view().uri);
    const params = readCode(uri);
    assert.equal(params.origin, 'https://shop.example');
    let askedOrigin: string | undefined, digitsSeen = '';
    const answered = answerCode({
      params, viaCamera: false,
      consent: async (o) => { askedOrigin = o; return true; },
      mint: (origin) => { const s = load(join(home, 'device.json')); const t = newTicket(npub, new URL(bunker.url.replace('bunker://', 'https://')).hostname, [relay]); (s.bunker!.tickets ??= []).push({ t: t.t, expires: t.expires, origin }); save(join(home, 'device.json'), s); return t; },
      sameDigits: async (d) => { digitsSeen = d; return d === await waitFor(() => shop.view().digits); },
    });
    const ticket = await answered;
    assert.equal(askedOrigin, 'https://shop.example');
    assert.match(digitsSeen, /^\d{5}$/);
    assert.deepEqual(await shop.run.done, ticket);
    assert.match(shop.asked(), new RegExp(`Sign in as ${npub.slice(0, 8)}…, through your signer`));
    const ev = await shop.signer().signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content: 'signed in by a scanned code' });
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub);
    assert.match((await cli(home, 'sites')).text, /https:\/\/shop\.example/);

    // 2. A ticket works once: a second site that got hold of it is refused.
    const thief = BunkerSigner.fromBunker(generateSecretKey(), { pubkey: ticket.signer, relays: ticket.relays, secret: ticket.t }); signers.push(thief);
    await assert.rejects(thief.connect(), /bad_secret/);

    // 3. Wrong digits: nothing is sent and the site is not signed in.
    const evil = site('https://evil.example');
    const p2 = readCode(await waitFor(() => evil.view().uri));
    let minted = 0;
    await assert.rejects(answerCode({ params: p2, viaCamera: false, consent: async () => true, mint: () => { minted++; return newTicket(npub, ticket.signer, [relay]); }, sameDigits: async () => false }), /did not match/);
    assert.equal(evil.view().state === 'done', false);
    evil.run.cancel();
    // Saying no: no ticket is even made.
    const nope = site('https://nope.example');
    const p3 = readCode(await waitFor(() => nope.view().uri));
    await assert.rejects(answerCode({ params: p3, viaCamera: false, consent: async () => false, mint: () => { minted++; return ticket; }, sameDigits: async () => true }), /Not allowed/);
    assert.equal(minted, 1);
    nope.run.cancel();

    // 4. The command line does the same, and signing the site out stops it.
    const blog = site('https://blog.example');
    const out = await cli(home, 'scan', await waitFor(() => blog.view().uri), '--yes');
    assert.match(out.text, /https:\/\/blog\.example can now sign as you/);
    await blog.run.done;
    assert.ok(verifyEvent(await blog.signer().signEvent({ kind: 1, created_at: 1700000000, tags: [], content: 'from the blog' })));
    assert.match((await cli(home, 'signout', 'blog.example')).text, /Signed out 1 site/);
    await assert.rejects(blog.signer().signEvent({ kind: 1, created_at: 1700000001, tags: [], content: 'after sign-out' }), /not_connected/);
    assert.ok(verifyEvent(await shop.signer().signEvent({ kind: 1, created_at: 1700000002, tags: [], content: 'the shop still works' })));

    // A code for something else is not a sign-in code.
    assert.throws(() => readCode(uri.replace('signer-ticket', 'nostr-nsec')), /not a sign-in code/);
  } finally {
    for (const s of signers) await Promise.race([s.close().catch(() => {}), new Promise((r) => setTimeout(r, 1000))]);
    bunker?.close(); await closeBox(b); await testRelay.close();
  }
});
