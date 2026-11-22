// The sealed signer (device-rs, `keykin` in Rust; SPEC 8d) against a throwaway box, with the Node command line as
// the phone. The signer is the debug build, run with its test chip (KEYKIN_SOFT_CHIP=1): no finger, no Secure
// Enclave. The real chip is one run by a person. Skipped when device-rs isn't built (cargo build in device-rs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';

const bin = new URL('../device-rs/target/debug/keykin', import.meta.url).pathname;
const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
const closeBox = (b: any) => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });

async function phone(home: string, ...argv: string[]) {
  const lines: string[] = [];
  await main(argv, (s) => lines.push(s), home);
  return lines.join('\n');
}

/** Runs the signer to the end (stdin given, then closed). Never left running: killed after 30 s. */
function signer(dir: string, args: string[], input = ''): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((done) => {
    const c = spawn(bin, args, { env: { ...process.env, KEYKIN_SOFT_CHIP: '1', KEYKIN_SIGNER_DIR: dir, KEYKIN_NO_BROWSER: '1' } });
    let out = '', err = '';
    c.stdout.on('data', (d) => (out += d)); c.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => c.kill('SIGKILL'), 30_000);
    c.on('close', (code) => { clearTimeout(t); done({ code, out, err }); });
    c.stdin.end(input);
  });
}

test('the sealed signer: join from a phone, sign, refuse what the box asks about, blocked, forget', { skip: !existsSync(bin) && 'device-rs is not built' }, async () => {
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  const mac = tmp('kk-signer-');
  let joining: ReturnType<typeof spawn> | undefined;
  try {
    const home = tmp('kk-phone-');
    const made = await phone(home, 'create', b.qr()!, 'Phone', '--username', 'signer', '--password', 'long enough pw');
    const npub = /npub \(hex\): ([0-9a-f]{64})/.exec(made)![1];

    // keykin join: it shows its invite and waits; the phone adds it, and the join code goes in where it waits.
    const joined = await new Promise<{ code: number | null; out: string }>((done, fail) => {
      const c = joining = spawn(bin, ['join', '--name', 'Test Mac (Terminal)'], { env: { ...process.env, KEYKIN_SOFT_CHIP: '1', KEYKIN_SIGNER_DIR: mac, KEYKIN_NO_BROWSER: '1' } });
      let out = '', sent = false;
      c.stderr.on('data', (d) => (out += d));
      c.stdout.on('data', async (d) => {
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
    assert.match(joined.out, /Joined\. This Mac signs as npub1/);
    assert.match(await phone(home, 'status'), /Test Mac \(Terminal\)/);

    // The file: mode 600, nothing in it that signs.
    const file = join(mac, 'device.json');
    assert.equal(statSync(file).mode & 0o777, 0o600);
    const f = JSON.parse(readFileSync(file, 'utf8'));
    assert.deepEqual(Object.keys(f).sort(), ['account', 'chip', 'key', 'name', 'sealed', 'v']);
    assert.equal(f.account.npub, npub);
    assert.ok(!('share' in f.account) && !('sk' in f));

    // Signs: a note, and the app handler that started this (kind 31990).
    const note = await signer(mac, ['sign', JSON.stringify({ kind: 1, content: 'from Terminal' })]);
    assert.equal(note.code, 0, note.err);
    const ev = JSON.parse(note.out);
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub); assert.equal(ev.content, 'from Terminal');
    const handler = await signer(mac, ['sign', '-'], JSON.stringify({ kind: 31990, tags: [['d', 'marble'], ['k', '1']], content: '{"name":"Marble"}' }));
    assert.equal(handler.code, 0, handler.err);
    assert.ok(verifyEvent(JSON.parse(handler.out)));

    // What the box asks about is never said Yes to here; level 2 is the phone's.
    const five = await signer(mac, ['sign', JSON.stringify({ kind: 5, tags: ['1', '2', '3', '4', '5'].map((n) => ['e', n.repeat(64)]) })]);
    assert.equal(five.code, 1);
    assert.match(five.err, /^Not signed: Delete 5 of your events\. keykin doesn’t say Yes for you: sign it in Marble or on your phone\./);
    const vanish = await signer(mac, ['sign', JSON.stringify({ kind: 62, tags: [['relay', 'ALL_RELAYS']] })]);
    assert.equal(vanish.code, 1);
    assert.match(vanish.err, /^Not signed: Ask relays to erase everything you have ever published\. Do this from your phone\./);

    // Another account's pubkey: refused before anything is asked.
    const other = await signer(mac, ['sign', JSON.stringify({ pubkey: 'ab'.repeat(32) })]);
    assert.equal(other.code, 1); assert.match(other.err, /pubkey/);

    const st = await signer(mac, ['status']);
    assert.match(st.out, /^npub1/); assert.match(st.out, new RegExp(npub)); assert.match(st.out, /Test Mac \(Terminal\)/);
    assert.match((await signer(mac, ['join'])).err, /already in an account/);

    // Blocked on the phone: refused, and it says how to clear the file.
    await phone(home, 'block', 'Test Mac (Terminal)');
    const blocked = await signer(mac, ['sign', '{}']);
    assert.equal(blocked.code, 1); assert.match(blocked.err, /blocked/); assert.match(blocked.err, /keykin forget/);

    assert.match((await signer(mac, ['forget'])).out, /Forgot this Mac’s piece/);
    assert.ok(!existsSync(file));
    assert.match((await signer(mac, ['sign', '{}'])).err, /keykin join/);
  } finally {
    if (joining && joining.exitCode === null) joining.kill('SIGKILL');
    await closeBox(b);
  }
});
