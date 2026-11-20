// Adding a device with one code (QRST `keykin-device`, SPEC 8b), end to end over a local relay and a box:
// the new device shows its code, a device in the account answers it, and the new device signs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { verifyEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';
import { keykinDevice, readAddCode, answerAddCode, showAddCode, inviteOf, withInvite, readInvite, type KeykinGift, type AddCodeView } from '../src/adddevice.ts';
import { hexToBytes, bytesToHex } from '../src/bytes.ts';

const qrstRepo = process.env.QRST_REPO ?? join(homedir(), 'qr-secret-transfer');
const relayTool = join(qrstRepo, 'tools/test-relay.mjs');
const vectors = join(qrstRepo, 'vectors/keykin-device.json');
const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
const closeBox = (b: any) => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
const waitFor = async <T>(get: () => T | undefined, ms = 20000): Promise<T> => { const end = Date.now() + ms; for (;;) { const v = get(); if (v !== undefined) return v; if (Date.now() > end) throw new Error('timed out waiting'); await new Promise((r) => setTimeout(r, 50)); } };

test('the profile matches qr-secret-transfer\'s vectors', { skip: !existsSync(vectors) && 'no keykin-device vectors beside this repo (QRST_REPO)' }, () => {
  const v = JSON.parse(readFileSync(vectors, 'utf8'));
  assert.equal(keykinDevice.encode({ join: v.join.value }), v.join.content);
  assert.equal(keykinDevice.encode({ nsec: hexToBytes(v.whole.nsec) }), v.whole.content);
  const w = keykinDevice.check(v.whole.content);
  assert.ok(w.ok && 'nsec' in w.value && bytesToHex(w.value.nsec) === v.whole.nsec);
  assert.equal(keykinDevice.render({ join: v.join.value }), v.join.render);
  for (const b of v.bad) assert.equal(keykinDevice.check(b.content).ok, false, b.why);
  assert.deepEqual(inviteOf(v.uri), readInvite(v.invite.text));
  assert.equal(withInvite(v.uri.slice(0, v.uri.indexOf('&invite=')), v.invite.text), v.uri);
  assert.equal(readAddCode(v.uri).invite.name, 'Galaxy Tab');
  assert.throws(() => readAddCode(v.uri.slice(0, v.uri.indexOf('&invite='))), /no device/);
});

test('a new device signs in with one code: a box account gives it a piece', { skip: !existsSync(relayTool) && 'the qr-secret-transfer repo is not beside this one', timeout: 90_000 }, async () => {
  const testRelay = await (await import(relayTool)).startRelay({});
  const relay: string = testRelay.url;
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });
  const lines: string[] = [];
  try {
    const old = tmp('kk-old-'), fresh = tmp('kk-new-');
    const say = (l: string[]) => (t: string) => l.push(t);
    await main(['create', b.qr()!, 'Laptop'], () => {}, old);
    // The new device shows its code and waits.
    const signingIn = main(['signin', relay, 'Tablet'], say(lines), fresh);
    signingIn.catch(() => {});
    const uri = await waitFor(() => lines.join('\n').match(/(https:\/\/marble\.syb\.lol\/add#\S+)/)?.[1]);
    assert.equal(readAddCode(uri).invite.name, 'Tablet');
    // The device in the account: pasted, so the digits are compared (here, the ones the new device printed).
    const added: string[] = [];
    await main(['add', uri, '--yes'], say(added), old);
    assert.match(added.join('\n'), /Digits: \d{5}/);
    assert.equal(added.join('\n').match(/Digits: (\d{5})/)![1], lines.join('\n').match(/Digits: (\d{5})/)![1]);
    assert.match(added.join('\n'), /Added Tablet\./);
    await signingIn;
    assert.match(lines.join('\n'), /Signed in\. npub1/);
    // The new device is on the list and signs with the box.
    const status: string[] = [];
    await main(['status'], say(status), fresh);
    assert.match(status.join('\n'), /Tablet \(this device\)/);
    const signed: string[] = [];
    await main(['sign', JSON.stringify({ kind: 1, content: 'from the tablet' })], say(signed), fresh);
    assert.ok(verifyEvent(JSON.parse(signed[0]!)));
  } finally { await closeBox(b); await testRelay.close?.(); }
});

test('an account with no box gives the whole key; a camera scan needs no digits', { skip: !existsSync(relayTool) && 'the qr-secret-transfer repo is not beside this one', timeout: 60_000 }, async () => {
  const testRelay = await (await import(relayTool)).startRelay({});
  try {
    const nsec = generateSecretKey(), member = generateSecretKey();
    const invite = JSON.stringify({ keykin: 2, invite: { key: getPublicKey(member), name: 'Tablet' } });
    let view: AddCodeView = { state: 'starting' };
    const shown = showAddCode({ invite, relays: [testRelay.url], baseUrl: 'https://marble.syb.lol/add', onView: (v) => { view = v; } });
    const uri = await waitFor(() => view.uri);
    let digitsAsked = false;
    await answerAddCode({
      code: readAddCode(uri), viaCamera: true,
      consent: async (inv) => inv.name === 'Tablet',
      sameDigits: async () => { digitsAsked = true; return true; },
      gift: async (): Promise<KeykinGift> => ({ nsec: nsec.slice() }),
    });
    const got = await shown.done;
    assert.equal(digitsAsked, false);
    assert.ok('nsec' in got && bytesToHex(got.nsec) === bytesToHex(nsec));
  } finally { await testRelay.close?.(); }
});

test('nothing is added when the person says no, or the digits differ', { skip: !existsSync(relayTool) && 'the qr-secret-transfer repo is not beside this one', timeout: 60_000 }, async () => {
  const testRelay = await (await import(relayTool)).startRelay({});
  try {
    const invite = JSON.stringify({ keykin: 2, invite: { key: getPublicKey(generateSecretKey()), name: 'Stranger' } });
    let view: AddCodeView = { state: 'starting' };
    const shown = showAddCode({ invite, relays: [testRelay.url], baseUrl: 'https://marble.syb.lol/add', onView: (v) => { view = v; } });
    shown.done.catch(() => {});
    const uri = await waitFor(() => view.uri);
    let gifts = 0;
    const gift = async (): Promise<KeykinGift> => { gifts++; return { nsec: generateSecretKey() }; };
    await assert.rejects(answerAddCode({ code: readAddCode(uri), viaCamera: true, consent: async () => false, sameDigits: async () => true, gift }), /Not added/);
    await assert.rejects(answerAddCode({ code: readAddCode(uri), viaCamera: false, consent: async () => true, sameDigits: async () => false, gift, timeoutMs: 20_000 }), /did not match/);
    assert.equal(gifts, 0);
    shown.cancel();
  } finally { await testRelay.close?.(); }
});
