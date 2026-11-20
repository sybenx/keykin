import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { verifyEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';
import * as D from '../src/device.ts';
import * as nip19 from 'nostr-tools/nip19';

const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
const closeBox = (b: any) => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
async function cli(home: string, ...argv: string[]) {
  const lines: string[] = [];
  const r = await main(argv, (s) => lines.push(s), home);
  return { text: lines.join('\n'), run: r as any };
}

test('two command-line devices: create, invite, add, join, sign, block, nsec', async () => {
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  try {
    const [mac, mini] = [tmp('kk-mac-'), tmp('kk-mini-')];
    const made = await cli(mac, 'create', b.qr()!, 'MacBook');
    const npub = /npub \(hex\): ([0-9a-f]{64})/.exec(made.text)![1];
    assert.equal(statSync(join(mac, 'device.json')).mode & 0o777, 0o600);
    await assert.rejects(cli(mac, 'create', b.qr() ?? '{}', 'Again'), /already in an account/);

    const invite = (await cli(mini, 'invite', 'Mac mini')).text;
    const joinText = (await cli(mac, 'add', invite)).text;
    assert.match((await cli(mini, 'join', joinText)).text, new RegExp(npub));

    const signed = JSON.parse((await cli(mini, 'sign', JSON.stringify({ kind: 1, content: 'from the mini', created_at: 1700000000 }))).text);
    assert.ok(verifyEvent(signed)); assert.equal(signed.pubkey, npub);

    const status = (await cli(mac, 'status')).text;
    assert.match(status, /MacBook \(this device\)/); assert.match(status, /Mac mini/); assert.match(status, /\(box\)/);
    await cli(mac, 'block', 'Mac mini');
    await assert.rejects(cli(mini, 'sign', '{}'), /blocked/);
    assert.match((await cli(mac, 'status')).text, /Mac mini  BLOCKED/);
    await cli(mac, 'unblock', 'Mac mini');
    await cli(mini, 'sign', '{}');

    const nsec = (await cli(mac, 'nsec')).text;
    assert.match(nsec, /^nsec1/);
    assert.equal(Buffer.from(schnorr.getPublicKey(nip19.decode(nsec).data as Uint8Array)).toString('hex'), npub);

    // Block, then cycle: the blocked device is gone for good and the other still signs.
    await cli(mac, 'block', 'Mac mini');
    assert.match((await cli(mac, 'cycle')).text, /cycled/);
    assert.doesNotMatch((await cli(mac, 'status')).text, /Mac mini/);
    await assert.rejects(cli(mini, 'sign', '{}'), /unknown_member/);
    assert.ok(verifyEvent(JSON.parse((await cli(mac, 'sign', '{"content":"after the cycle"}')).text)));
  } finally { await closeBox(b); }
});

test('importing a key keeps the whole key as a backup until the person forgets it', async () => {
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  try {
    const home = tmp('kk-mac-');
    const sk = generateSecretKey(), nsec = nip19.nsecEncode(sk), npub = getPublicKey(sk);
    const done = (await cli(home, 'import', b.qr()!, nsec, 'MacBook')).text;
    assert.match(done, new RegExp(nip19.npubEncode(npub))); assert.match(done, /still holds the whole key/);
    const saved = () => JSON.parse(readFileSync(join(home, 'device.json'), 'utf8'));
    assert.equal(saved().nsec, Buffer.from(sk).toString('hex'));                 // kept, in the 0600 state file
    assert.equal(statSync(join(home, 'device.json')).mode & 0o777, 0o600);
    const ev = JSON.parse((await cli(home, 'sign', '{"content":"same me"}')).text);
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub);
    // Nothing forgets it but the person.
    await cli(home, 'status'); await cli(home, 'sign', '{}');
    assert.equal(saved().nsec, Buffer.from(sk).toString('hex'));
    assert.match((await cli(home, 'forget-key')).text, /Forgotten/);
    assert.equal(saved().nsec, undefined);
    assert.match((await cli(home, 'forget-key')).text, /holds no whole key/);
    assert.ok(verifyEvent(JSON.parse((await cli(home, 'sign', '{"content":"still me"}')).text)));
  } finally { await closeBox(b); }
});

test('moving the account to another box: transfer on one device, moved on the others', async () => {
  const [b1, b2] = [await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} }), await startBox({ dir: tmp('kk-box2-'), port: 0, log: () => {} })];
  try {
    const [mac, mini, other] = [tmp('kk-mac-'), tmp('kk-mini-'), tmp('kk-other-')];
    const npub = /npub \(hex\): ([0-9a-f]{64})/.exec((await cli(mac, 'create', b1.qr()!, 'MacBook')).text)![1];
    await cli(mini, 'join', (await cli(mac, 'add', (await cli(mini, 'invite', 'Mac mini')).text)).text);
    const before = (await cli(mac, 'nsec')).text;
    // The new box already holds someone else's account, so its admin makes a code for this one.
    await cli(other, 'create', b2.qr()!, 'Someone else');
    const code = b2.box.newSetupCode(`http://127.0.0.1:${b2.port}`, Math.floor(Date.now() / 1000));
    await assert.rejects(cli(mac, 'transfer', b1.box.newSetupCode(`http://127.0.0.1:${b1.port}`, Math.floor(Date.now() / 1000))), /already/);

    const moved = (await cli(mac, 'transfer', code)).text;
    const joinText = moved.split('\n').pop()!;
    assert.deepEqual(JSON.parse(joinText).join, { addr: `http://127.0.0.1:${b2.port}`, boxKey: b2.box.state.key, npub });
    const saved = JSON.parse(readFileSync(join(mac, 'device.json'), 'utf8'));
    assert.equal(saved.addr, `http://127.0.0.1:${b2.port}`); assert.equal(saved.held.boxKey, b2.box.state.key);
    assert.ok(verifyEvent(JSON.parse((await cli(mac, 'sign', '{"content":"on the new box"}')).text)));
    assert.equal((await cli(mac, 'nsec')).text, before);                         // the same key
    assert.match((await cli(mac, 'status')).text, /Mac mini/);
    assert.equal(b2.box.accounts().length, 2);
    assert.ok(!b2.box.state.accounts[npub].members.some((m) => m.key === b1.box.state.key));

    // The mini is told, checks the new box, and catches up on its first request there.
    await assert.rejects(cli(mini, 'moved', joinText.replace(npub, 'f'.repeat(64))), /another account/);
    await assert.rejects(cli(mini, 'moved', joinText.replace(b2.box.state.key, b1.box.state.key)), /another key/);
    assert.match((await cli(mini, 'moved', joinText)).text, /new box now/);
    const piece = JSON.parse(readFileSync(join(mini, 'device.json'), 'utf8')).held.share;
    const signed = JSON.parse((await cli(mini, 'sign', '{"content":"caught up"}')).text);
    assert.ok(verifyEvent(signed)); assert.equal(signed.pubkey, npub);
    const after = JSON.parse(readFileSync(join(mini, 'device.json'), 'utf8')).held;
    assert.notEqual(after.share, piece); assert.equal(after.epoch, 1);
    // The old box's piece no longer fits: the mini cannot sign with it.
    const old = JSON.parse(readFileSync(join(mini, 'device.json'), 'utf8'));
    old.addr = `http://127.0.0.1:${b1.port}`; old.held.boxKey = b1.box.state.key;
    const stale = tmp('kk-stale-');
    (await import('node:fs')).writeFileSync(join(stale, 'device.json'), JSON.stringify(old));
    await assert.rejects(cli(stale, 'sign', '{"content":"with the old box"}'), /bad_piece/);
  } finally { await closeBox(b1); await closeBox(b2); }
});

test('with the box off, a computer that stays on helps the other devices sign', async () => {
  const dir = tmp('kk-box-');
  let b = await startBox({ dir, port: 0, log: () => {} });
  const port = b.port;
  let helper: any;
  try {
    const [mac, mini, old] = [tmp('kk-mac-'), tmp('kk-mini-'), tmp('kk-old-')];
    await cli(mac, 'create', b.qr()!, 'MacBook');
    for (const [home, name] of [[mini, 'Mac mini'], [old, 'Old laptop']] as const) {
      await cli(home, 'join', (await cli(mac, 'add', (await cli(home, 'invite', name)).text)).text);
      await cli(home, 'sign', '{}');
    }
    const hp = 21000 + Math.floor(Math.random() * 20000);
    helper = (await cli(mac, 'serve', String(hp), `http://127.0.0.1:${hp}`)).run;
    await cli(old, 'block', 'Old laptop').catch(() => {});       // (a device may not block itself out of turn; use the Mac)
    await cli(mini, 'block', 'Old laptop');
    await helper.refresh();
    await cli(mini, 'status');                                   // the mini learns where the Mac listens

    await closeBox(b);                                           // the box goes off
    const signed = JSON.parse((await cli(mini, 'sign', JSON.stringify({ content: 'signed with no box', created_at: 1700000000 }))).text);
    assert.ok(verifyEvent(signed));
    // The blocked one gets no help from the Mac either, and nothing but signing works without the box.
    await assert.rejects(cli(old, 'sign', '{}'), /blocked|fetch failed|no_box/);
    await assert.rejects(cli(mini, 'nsec'), /fetch failed|no_box|ECONNREFUSED/);
    await assert.rejects(cli(mini, 'status'), /fetch failed|ECONNREFUSED/);

    b = await startBox({ dir, port, log: () => {} });             // and comes back
    assert.ok(verifyEvent(JSON.parse((await cli(mini, 'sign', '{"content":"box is back"}')).text)));
    assert.match((await cli(mini, 'status')).text, /Old laptop  BLOCKED/);
  } finally { helper?.close(); await closeBox(b); }
});

test('the agent: a computer left on does what the account page asks, and its sites show up there', { skip: spawnSync('which', ['nak']).status !== 0 && 'nak is not installed', timeout: 60_000 }, async () => {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const relayProc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  const relay = `ws://127.0.0.1:${port}`;
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  let agent: any, site: BunkerSigner | undefined;
  try {
    for (let k = 0; k < 50; k++) {
      try { const w = new WebSocket(relay); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
      catch { await new Promise((r) => setTimeout(r, 100)); }
    }
    const home = tmp('kk-mac-'), now = () => Math.floor(Date.now() / 1000);
    const npub = /([0-9a-f]{64})/.exec((await cli(home, 'create', b.qr()!, 'MacBook')).text)![1];
    // The person sets a password and signs in to the account page somewhere else.
    b.box.setLogin(npub, 'aaron', 'a'.repeat(32), D.passwordCheck(await D.passwordVerifier('pw pw pw pw', 'a'.repeat(32))));
    const session = b.page.call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw pw', 'a'.repeat(32)) }, now()).session;
    agent = (await cli(home, 'agent', relay)).run;

    // "Ask my phone for a link": the agent answers, and a site signs in with the link.
    const { note: id } = b.page.call({ call: 'note_put', session, kind: 'bunker', text: '' }, now());
    await agent.tick();
    const link = b.page.call({ call: 'note_get', session, note: id }, now()).result;
    assert.match(link, /^bunker:\/\//);
    const siteKey = generateSecretKey();
    site = BunkerSigner.fromBunker(siteKey, (await parseBunkerInput(link))!);
    await site.connect();
    await agent.tick();                       // the site is reported to the box
    assert.ok(verifyEvent(await site.signEvent({ kind: 1, created_at: now(), tags: [], content: 'from a work PC' })));
    // The account page now lists that site, and when it was last used.
    let me = b.page.call({ call: 'me', session }, now());
    assert.equal(me.grants.length, 1); assert.match(me.grants[0].name, /^A site \(/); assert.equal(me.grants[0].deviceName, 'MacBook'); assert.ok(me.grants[0].last);
    // Revoked there: the site is refused at once, and the agent forgets it.
    b.page.call({ call: 'revoke', session, grant: me.grants[0].id }, now());
    await assert.rejects(site.signEvent({ kind: 1, created_at: now(), tags: [], content: 'after the revoke' }), /revoked/);
    await agent.tick();
    assert.match((await cli(home, 'sites')).text, /No site is signed in/);

    // "Add a device" from the page: the agent adds it with nobody at the keyboard.
    const pc = tmp('kk-pc-');
    const { note: id2 } = b.page.call({ call: 'note_put', session, kind: 'invite', text: (await cli(pc, 'invite', 'Work PC')).text }, now());
    await agent.tick();
    // Added from the page: the join text and the six digits the page shows (SPEC 11.6), typed as `keykin join '<join>' <code>`.
    const got2 = b.page.call({ call: 'note_get', session, note: id2 }, now());
    await assert.rejects(cli(pc, 'join', got2.result), /not_approved|wrong_code/);
    await cli(pc, 'join', got2.result, got2.approval.short);
    assert.ok(verifyEvent(JSON.parse((await cli(pc, 'sign', '{"content":"hi from the work PC"}')).text)));
    // Removing blocked devices asks for a Yes. Nobody is at this keyboard, so it is No, and that browser is signed out.
    b.page.call({ call: 'block', session, key: b.box.only()!.members.find((m) => m.name === 'Work PC')!.key }, now());
    b.page.call({ call: 'note_put', session, kind: 'cycle', text: '' }, now());
    await agent.tick();
    assert.deepEqual(b.page.call({ call: 'me', session }, now()), { error: 'login' });
    assert.equal(b.box.only()!.epoch, 0);
  } finally { await site?.close(); agent?.close(); await closeBox(b); relayProc.kill(); }
});

// A relay on this machine, from nak. Resolves once it listens.
async function nakRelay() {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  const url = `ws://127.0.0.1:${port}`;
  for (let k = 0; k < 50; k++) {
    try { const w = new WebSocket(url); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
    catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  return { url, kill: () => proc.kill() };
}

test('the agent answers a nostrconnect:// code from the account page, on the relay the code names', { skip: spawnSync('which', ['nak']).status !== 0 && 'nak is not installed', timeout: 60_000 }, async () => {
  const [mine, theirs] = [await nakRelay(), await nakRelay()];       // the agent's own relay, and the one the site uses
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  let agent: any, site: BunkerSigner | undefined;
  try {
    const home = tmp('kk-mac-'), now = () => Math.floor(Date.now() / 1000);
    const npub = /([0-9a-f]{64})/.exec((await cli(home, 'create', b.qr()!, 'MacBook')).text)![1];
    b.box.setLogin(npub, 'aaron', 'a'.repeat(32), D.passwordCheck(await D.passwordVerifier('pw pw pw pw', 'a'.repeat(32))));
    const session = b.page.call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw pw', 'a'.repeat(32)) }, now()).session;
    agent = (await cli(home, 'agent', mine.url)).run;

    // The site shows its code and waits for a signer to answer on its relay.
    const siteKey = generateSecretKey(), secret = 'a1b2c3d4';
    const uri = createNostrConnectURI({ clientPubkey: getPublicKey(siteKey), relays: [theirs.url], secret, name: 'Work site', url: 'https://work.example/app' });
    const waiting = BunkerSigner.fromURI(siteKey, uri, {}, 20_000);
    await new Promise((r) => setTimeout(r, 300));
    // The person pastes it into the account page; the agent picks the note up and answers with the secret.
    const { note: id } = b.page.call({ call: 'note_put', session, kind: 'nostrconnect', text: uri }, now());
    await agent.tick();
    assert.deepEqual(b.page.call({ call: 'note_get', session, note: id }, now()), { ok: true, state: 'done', result: 'ok' });
    site = await waiting;
    assert.equal(await site.getPublicKey(), npub);
    const ev = await site.signEvent({ kind: 1, created_at: now(), tags: [], content: 'signed in by a pasted code' });
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub);
    const friendSk = generateSecretKey();
    assert.equal(nip44.decrypt(await site.nip44Encrypt(getPublicKey(friendSk), 'psst'), nip44.utils.getConversationKey(friendSk, npub)), 'psst');

    // It is a grant: listed on the account page under the site's own address, and it can be limited and revoked there.
    await agent.tick();
    const me = b.page.call({ call: 'me', session }, now());
    assert.deepEqual(me.grants.map((g: any) => [g.name, g.deviceName]), [['https://work.example', 'MacBook']]);
    assert.match((await cli(home, 'sites')).text, /https:\/\/work\.example/);
    b.page.call({ call: 'limit', session, grant: me.grants[0].id, to: 'posts' }, now());
    await assert.rejects(site.signEvent({ kind: 3, created_at: now(), tags: [], content: '' }), /not_allowed/);
    b.page.call({ call: 'revoke', session, grant: me.grants[0].id }, now());
    await assert.rejects(site.signEvent({ kind: 1, created_at: now(), tags: [], content: 'after the revoke' }), /revoked/);
    await assert.rejects(site.signEvent({ kind: 1, created_at: now(), tags: [], content: 'and after that' }), /not_connected/);
    assert.match((await cli(home, 'sites')).text, /No site is signed in/);

    // A code that is not one is answered as not done, and nothing is let in.
    const { note: bad } = b.page.call({ call: 'note_put', session, kind: 'nostrconnect', text: 'nostrconnect://nothex?relay=ws%3A%2F%2Fx&secret=1' }, now());
    await agent.tick();
    assert.equal(b.page.call({ call: 'note_get', session, note: bad }, now()).state, 'waiting');
  } finally { await site?.close(); agent?.close(); await closeBox(b); mine.kill(); theirs.kill(); }
});

test('a site signs in through the remote signer over a relay', { skip: spawnSync('which', ['nak']).status !== 0 && 'nak is not installed' }, async () => {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const relayProc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  const relay = `ws://127.0.0.1:${port}`;
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  let bunker: any, site: BunkerSigner | undefined;
  try {
    for (let k = 0; k < 50; k++) {   // wait for the relay to listen
      try { const w = new WebSocket(relay); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
      catch { await new Promise((r) => setTimeout(r, 100)); }
    }
    const home = tmp('kk-mac-');
    const npub = /([0-9a-f]{64})/.exec((await cli(home, 'create', b.qr()!, 'MacBook')).text)![1];
    const started = await cli(home, 'bunker', relay);
    bunker = started.run;
    const url = /bunker:\/\/\S+/.exec(started.text)![0];

    // The site's side, with the ordinary NIP-46 client from nostr-tools.
    const siteKey = generateSecretKey();
    site = BunkerSigner.fromBunker(siteKey, (await parseBunkerInput(url))!);
    await site.connect();
    assert.equal(await site.getPublicKey(), npub);
    const ev = await site.signEvent({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [['t', 'keykin']], content: 'signed for a site' });
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub);

    // Messages through the signer match an ordinary key on the other side.
    const friendSk = generateSecretKey(), friend = getPublicKey(friendSk);
    const sealed = await site.nip44Encrypt(friend, 'hello friend');
    assert.equal(nip44.decrypt(sealed, nip44.utils.getConversationKey(friendSk, npub)), 'hello friend');
    assert.equal(await site.nip44Decrypt(friend, nip44.encrypt('hello back', nip44.utils.getConversationKey(friendSk, npub))), 'hello back');

    // A stranger without the secret gets nowhere.
    const stranger = BunkerSigner.fromBunker(generateSecretKey(), { ...(await parseBunkerInput(url))!, secret: 'wrong' });
    await assert.rejects(stranger.connect(), /bad_secret/);
    await stranger.close();

    // Signing the site out: it is refused from then on, and the old link no longer lets it back in.
    assert.match((await cli(home, 'sites')).text, new RegExp(getPublicKey(siteKey)));
    assert.match((await cli(home, 'signout', getPublicKey(siteKey).slice(0, 12))).text, /Signed out 1 site/);
    await assert.rejects(site.signEvent({ kind: 1, created_at: 1, tags: [], content: 'after sign-out' }), /not_connected/);
    const again = BunkerSigner.fromBunker(siteKey, (await parseBunkerInput(url))!);
    await assert.rejects(again.connect(), /bad_secret/);
    await again.close();
  } finally {
    await site?.close(); bunker?.close(); await closeBox(b); relayProc.kill();
  }
});

test('command line: a child key signs as its own npub, on either device', async () => {
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  try {
    const [mac, mini] = [tmp('kk-mac-'), tmp('kk-mini-')];
    const npub = /npub \(hex\): ([0-9a-f]{64})/.exec((await cli(mac, 'create', b.qr()!, 'MacBook')).text)![1];
    assert.match((await cli(mac, 'child')).text, /No child keys yet/);
    const child = /npub \(hex\): ([0-9a-f]{64})/.exec((await cli(mac, 'child', 'home')).text)![1];
    assert.notEqual(child, npub);
    assert.match((await cli(mac, 'child')).text, /home\s+npub1/);
    const ev = JSON.parse((await cli(mac, 'sign', '{"content":"from home"}', 'home')).text);
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, child);
    // Signing with no label is still the account.
    assert.equal(JSON.parse((await cli(mac, 'sign', '{"content":"me"}')).text).pubkey, npub);
    // A second device gets the same child without being told anything about it.
    await cli(mini, 'join', (await cli(mac, 'add', (await cli(mini, 'invite', 'Mac mini')).text)).text);
    const ev2 = JSON.parse((await cli(mini, 'sign', '{"content":"also home"}', 'home')).text);
    assert.ok(verifyEvent(ev2)); assert.equal(ev2.pubkey, child);
  } finally { await closeBox(b); }
});
