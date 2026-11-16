import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1.js';
import { startBox } from '../box/server.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';
import { hexToBytes } from '../src/bytes.ts';

test('over real HTTP: scan the QR, create, sign, restart from the state file, sign again', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'keykin-box-'));
  let b = await startBox({ dir, port: 0, log: () => {} });
  const stop = () => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
  try {
    const qr = D.readQr(b.qr()!);
    const send: D.Send = async (r) => (await fetch(`${qr.addr}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: { connection: 'close' } })).json();
    const phone: D.Me = { ...newMemberKey(), name: 'Phone', ...softwareChip() };
    const held = await D.createWithBox(phone, qr, send);

    const ev = { pubkey: held.npub, created_at: Math.floor(Date.now() / 1000), kind: 1, tags: [['t', 'keykin']], content: 'first note' };
    const s1 = await D.signEvent(phone, held, ev, send);
    assert.ok(schnorr.verify(hexToBytes(s1.sig), hexToBytes(s1.id), hexToBytes(held.npub)));

    await stop();
    b = await startBox({ dir, port: qr.addr.split(':').pop() as any * 1, log: () => {} });
    assert.equal(b.qr(), null);
    const s2 = await D.signEvent(phone, held, { ...ev, content: 'after restart' }, send);
    assert.ok(schnorr.verify(hexToBytes(s2.sig), hexToBytes(s2.id), hexToBytes(held.npub)));
    assert.match(await (await fetch(`${qr.addr}/`, { headers: { connection: 'close' } })).text(), /Set up/);
  } finally { await stop(); }
});
