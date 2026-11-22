// `keykin dm` (device-rs, SPEC 8d) against a throwaway box and a throwaway relay: a private message from a test
// account to a test key, opened by the reader with nostr-tools, and the account's own copy read back with
// `keykin decrypt`. The relay is `nak serve` (in memory). Skipped when device-rs isn't built or nak isn't installed.
// Nothing here touches a real account or a public relay: lookups go to the throwaway relay only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure';
import { unwrapEvent } from 'nostr-tools/nip59';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';

const bin = new URL('../device-rs/target/debug/keykin', import.meta.url).pathname;
const hasNak = spawnSync('nak', ['--version']).status === 0;
const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
const closeBox = (b: any) => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });

async function phone(home: string, ...argv: string[]) {
  const lines: string[] = [];
  await main(argv, (s) => lines.push(s), home);
  return lines.join('\n');
}

function signer(dir: string, env: Record<string, string>, args: string[], input = ''): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((done) => {
    const c = spawn(bin, args, { env: { ...process.env, KEYKIN_SOFT_CHIP: '1', KEYKIN_SIGNER_DIR: dir, KEYKIN_NO_BROWSER: '1', ...env } });
    let out = '', err = '';
    c.stdout.on('data', (d) => (out += d)); c.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => c.kill('SIGKILL'), 30_000);
    c.on('close', (code) => { clearTimeout(t); done({ code, out, err }); });
    c.stdin.end(input);
  });
}

/** One request to the relay: publish (`EVENT`) and wait for OK, or query (`REQ`) up to EOSE. */
function relay(url: string, msg: any[]): Promise<any[]> {
  return new Promise((done, fail) => {
    const ws = new WebSocket(url);
    const got: any[] = [];
    const t = setTimeout(() => { ws.close(); fail(new Error('relay timeout')); }, 5000);
    ws.onerror = () => { clearTimeout(t); fail(new Error('relay error')); };
    ws.onopen = () => ws.send(JSON.stringify(msg));
    ws.onmessage = (m) => {
      const v = JSON.parse(String(m.data));
      if (v[0] === 'EVENT') got.push(v[2]);
      if (v[0] === 'OK' || v[0] === 'EOSE' || v[0] === 'CLOSED') { clearTimeout(t); ws.close(); done(v[0] === 'OK' ? [v] : got); }
    };
  });
}

async function startRelay(): Promise<{ url: string; proc: ChildProcess }> {
  for (let tries = 0; tries < 5; tries++) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    const proc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
    const url = `ws://127.0.0.1:${port}`;
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 100));
      if (proc.exitCode !== null) break;
      try { await relay(url, ['REQ', 'up', { limit: 0 }]); return { url, proc }; } catch {}
    }
    proc.kill('SIGKILL');
  }
  throw new Error('nak serve did not start');
}

test('keykin dm: a private message from a test account, read by its reader and by the account', { skip: (!existsSync(bin) && 'device-rs is not built') || (!hasNak && 'nak is not installed') }, async () => {
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  const mac = tmp('kk-signer-');
  let joining: ChildProcess | undefined, r: { url: string; proc: ChildProcess } | undefined;
  try {
    r = await startRelay();
    const env = { KEYKIN_LOOKUP_RELAYS: r.url };
    const home = tmp('kk-phone-');
    const made = await phone(home, 'create', b.qr()!, 'Phone', '--username', 'dmtest', '--password', 'long enough pw');
    const npub = /npub \(hex\): ([0-9a-f]{64})/.exec(made)![1];

    const joined = await new Promise<{ code: number | null; out: string }>((done, fail) => {
      const c = joining = spawn(bin, ['join', '--name', 'Test Mac (Terminal)'], { env: { ...process.env, KEYKIN_SOFT_CHIP: '1', KEYKIN_SIGNER_DIR: mac, KEYKIN_NO_BROWSER: '1' } });
      let out = '', sent = false;
      c.stderr!.on('data', (d) => (out += d));
      c.stdout!.on('data', async (d) => {
        out += d;
        const inv = /Invite \(for your phone’s Add a device\): (\{.*\})/.exec(out);
        if (inv && !sent) {
          sent = true;
          try { c.stdin!.write((await phone(home, 'add', inv[1])).trim() + '\n'); } catch (e) { fail(e); }
        }
      });
      c.on('close', (code) => done({ code, out }));
    });
    assert.equal(joined.code, 0, joined.out);

    // The reader: a key made for this test, which reads private messages on the throwaway relay.
    const readerSk = generateSecretKey();
    const reader = getPublicKey(readerSk);
    const readerNpub = (await import('nostr-tools/nip19')).npubEncode(reader);

    // Nowhere listed: nothing is asked, nothing sent.
    const nowhere = await signer(mac, env, ['dm', readerNpub, 'hello?']);
    assert.equal(nowhere.code, 1);
    assert.match(nowhere.err, /lists no relays for private messages/);

    await relay(r.url, ['EVENT', finalizeEvent({ kind: 10050, created_at: Math.floor(Date.now() / 1000), tags: [['relay', r.url]], content: '' }, readerSk)]);
    await relay(r.url, ['EVENT', finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [], content: '{"name":"Test Reader"}' }, readerSk)]);
    // The account lists no relays of its own here (setting them asks for a Yes on the phone): its copy isn't kept.
    const text = 'Hello from Terminal 👋\nsecond line';
    const sent = await signer(mac, env, ['dm', '--for', 'the dm test', readerNpub, '-'], text + '\n');
    assert.equal(sent.code, 0, sent.err + sent.out);
    assert.match(sent.out, new RegExp(`^Sent to Test Reader \\(npub1.*\\): ${r.url}$`, 'm'));
    assert.match(sent.out, /^Your copy: not kept/m);

    // The reader's copy: a gift wrap to the reader, not signed by the account, that opens to the message.
    const toReader = await relay(r.url, ['REQ', 'w', { kinds: [1059], '#p': [reader] }]);
    assert.equal(toReader.length, 1);
    const w = toReader[0];
    assert.ok(verifyEvent(w)); assert.notEqual(w.pubkey, npub);
    const rumor = unwrapEvent(w, readerSk) as any;
    assert.equal(rumor.kind, 14); assert.equal(rumor.pubkey, npub); assert.equal(rumor.content, text);
    assert.deepEqual(rumor.tags, [['p', reader]]);
    // ... and nak opens it too.
    const hex = Buffer.from(readerSk).toString('hex');
    const byNak = spawnSync('nak', ['gift', 'unwrap'], { input: JSON.stringify(w), encoding: 'utf8', env: { ...process.env, NOSTR_SECRET_KEY: hex } });
    assert.equal(JSON.parse(byNak.stdout).content, text, byNak.stderr);

    // --relay: both copies go there. The account's copy opens through keykin decrypt: the wrap, then the seal.
    const again = await signer(mac, env, ['dm', '--relay', r.url, reader, 'and again']);
    assert.equal(again.code, 0, again.err + again.out);
    assert.match(again.out, new RegExp(`^Your copy: ${r.url}$`, 'm'));
    assert.equal((await relay(r.url, ['REQ', 'w2', { kinds: [1059], '#p': [reader] }])).length, 2);
    const mine = await relay(r.url, ['REQ', 'm', { kinds: [1059], '#p': [npub] }]);
    assert.equal(mine.length, 1);
    const seal = await signer(mac, env, ['decrypt', mine[0].pubkey, mine[0].content]);
    assert.equal(seal.code, 0, seal.err);
    const s = JSON.parse(seal.out);
    assert.ok(verifyEvent(s)); assert.equal(s.kind, 13); assert.equal(s.pubkey, npub);
    const inner = await signer(mac, env, ['decrypt', npub, s.content]);
    assert.equal(inner.code, 0, inner.err);
    assert.equal(JSON.parse(inner.out).content, 'and again');
    assert.deepEqual(JSON.parse(inner.out).tags, [['p', reader]]);

    // encrypt and decrypt are each other's inverse, and agree with nostr-tools.
    const enc = await signer(mac, env, ['encrypt', reader, 'just this']);
    assert.equal(enc.code, 0, enc.err);
    const { v2 } = await import('nostr-tools/nip44');
    assert.equal(v2.decrypt(enc.out.trim(), v2.utils.getConversationKey(readerSk, npub)), 'just this');
  } finally {
    if (joining && joining.exitCode === null) joining.kill('SIGKILL');
    r?.proc.kill('SIGKILL');
    await closeBox(b);
  }
});
