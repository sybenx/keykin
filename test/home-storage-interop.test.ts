// The Home section's file server calls (login/static/home.js) against a real Keykin Storage with /manage (0.3.0).
// Runs only with KEYKIN_STORAGE_DIR set to a checkout of it (with its node_modules); it is started on a loopback
// port in a temp folder and stopped at the end, failed runs included.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { npubEncode } from 'nostr-tools/nip19';

const dir = process.env.KEYKIN_STORAGE_DIR;
const box: any = {};
new Function('globalThis', readFileSync(join(import.meta.dirname, '../login/static/home.js'), 'utf8'))(box);
const K = box.KeykinHome;
const freePort = async () => { const { createServer } = await import('node:net'); const s = createServer(); await new Promise<void>((r) => s.listen(0, '127.0.0.1', r)); const p = (s.address() as any).port; await new Promise((r) => s.close(r)); return p; };

test('Home section calls against a real Keykin Storage /manage', { skip: (!dir || !existsSync(join(dir, 'src/main.ts'))) && 'set KEYKIN_STORAGE_DIR to a Keykin Storage 0.3.0 checkout', timeout: 60_000 }, async () => {
  const sk = generateSecretKey(), owner = getPublicKey(sk), signer = { signEvent: async (t: any) => finalizeEvent(t, sk) };
  const otherSk = generateSecretKey(), other = { signEvent: async (t: any) => finalizeEvent(t, otherSk) };
  const port = await freePort(), url = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['src/main.ts'], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, STORAGE_PUBLIC_URL: url, STORAGE_OWNER: npubEncode(owner), STORAGE_DIR: mkdtempSync(join(tmpdir(), 'kk-storage-')), STORAGE_ADDR: '127.0.0.1', STORAGE_PORT: String(port) } });
  let log = ''; child.stdout.on('data', (b) => { log += b; }); child.stderr.on('data', (b) => { log += b; });
  try {
    for (let k = 0; k < 100; k++) { try { await fetch(url + '/manage/info'); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
    const info = await K.storageInfo(url);
    assert.match(info.pubkey, /^[0-9a-f]{64}$/, log); assert.equal(info.home, null);

    // Two files from the owner (BUD-02), then one deleted (BUD-12): it goes to the bin.
    const put = async (text: string) => {
      const x = createHash('sha256').update(text).digest('hex'), now = Math.floor(Date.now() / 1000);
      const a = finalizeEvent({ kind: 24242, created_at: now - 1, tags: [['t', 'upload'], ['x', x], ['server', '127.0.0.1'], ['expiration', String(now + 600)]], content: 'upload' }, sk);
      const r = await fetch(url + '/upload', { method: 'PUT', body: text, headers: { authorization: 'Nostr ' + Buffer.from(JSON.stringify(a)).toString('base64url'), 'content-type': 'application/octet-stream', 'x-sha-256': x } });
      assert.ok(r.status === 201 || r.status === 200, `${r.status} ${await r.text()} ${log}`);
      return x;
    };
    const keep = await put('a photo'), gone = await put('another photo');
    const now = Math.floor(Date.now() / 1000);
    const d = finalizeEvent({ kind: 24242, created_at: now - 1, tags: [['t', 'delete'], ['x', gone], ['server', '127.0.0.1'], ['expiration', String(now + 600)]], content: 'delete' }, sk);
    assert.ok([200, 204].includes((await fetch(`${url}/${gone}`, { method: 'DELETE', headers: { authorization: 'Nostr ' + Buffer.from(JSON.stringify(d)).toString('base64url') } })).status));

    const m = K.manageUrl(url);
    const usage = await K.call(signer, m, 'usage', []);
    assert.equal(K.usedBy(usage)[owner].blobs, 2, JSON.stringify(usage));            // the bin still counts against whoever let go of it
    const bin = await K.call(signer, m, 'bin', []);
    assert.deepEqual(bin.items.map((x: any) => x.sha256), [gone]);
    assert.equal(bin.more, false);
    assert.deepEqual(K.binByPerson(bin).map((g: any) => [g.pubkey, g.items.length]), [[owner, 1]]);
    assert.deepEqual(await K.call(signer, m, 'restore', [[gone]]), { restored: 1 });
    assert.deepEqual((await K.call(signer, m, 'bin', [])).items, []);
    // erase takes any file, as the box's own `erase` command does; the page only ever sends what is in the bin.
    assert.deepEqual(await K.call(signer, m, 'erase', [[keep]]), { erased: 1 });
    assert.equal(K.usedBy(await K.call(signer, m, 'usage', []))[owner].blobs, 1);
    // Anyone else: one refusal, whatever they ask.
    for (const method of ['usage', 'bin', 'erase'])
      await assert.rejects(K.call(other, m, method, method === 'erase' ? [[keep]] : []), { message: 'this key may not manage this box', status: 401 });
  } finally {
    child.kill();
    await new Promise((r) => (child.exitCode !== null ? r(null) : child.once('exit', r)));
  }
});
