import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { verifyEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';
import { hexToBytes } from '../src/bytes.ts';

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
    assert.equal(Buffer.from(schnorr.getPublicKey(hexToBytes(nsec))).toString('hex'), npub);
  } finally { await closeBox(b); }
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
  } finally {
    await site?.close(); bunker?.close(); await closeBox(b); relayProc.kill();
  }
});
