import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1.js';
import { startBox } from '../box/server.ts';
import { createAccount, issuePiece, commitmentOf } from '../src/account.ts';
import { newMemberKey, seal } from '../src/member.ts';
import { signEvent } from '../src/device.ts';
import { scalarHex } from '../src/curve.ts';
import { hexToBytes } from '../src/bytes.ts';

test('over real HTTP: set up, sign, restart from the state file, sign again', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'keykin-box-'));
  const now = () => Math.floor(Date.now() / 1000);
  let b = await startBox({ dir, port: 0, log: () => {} });
  const send = (port: number) => async (r: any) => (await fetch(`http://127.0.0.1:${port}/keykin`, { method: 'POST', body: JSON.stringify(r) })).json();

  const a = createAccount();
  const phone = { p: { C: a.C, ...issuePiece(a) }, ...newMemberKey() };
  const bp = issuePiece(a);
  const r = await send(b.port)(seal({ op: 'setup', code: b.code, commitment: commitmentOf(a), i: bp.i, share: scalarHex(bp.share),
    boxKey: newMemberKey().key, deviceIndex: phone.p.i, deviceName: 'Phone' }, phone.sk, now()));
  assert.equal(r.ok, true);

  const ev = { pubkey: a.npub, created_at: now(), kind: 1, tags: [['t', 'keykin']], content: 'first note' };
  const s1 = await signEvent(phone.p, phone.sk, ev, send(b.port), now());
  assert.ok(schnorr.verify(hexToBytes(s1.sig), hexToBytes(s1.id), hexToBytes(a.npub)));

  await new Promise((done) => b.server.close(done));
  b = await startBox({ dir, port: 0, log: () => {} });
  const s2 = await signEvent(phone.p, phone.sk, { ...ev, content: 'after restart' }, send(b.port), now());
  assert.ok(schnorr.verify(hexToBytes(s2.sig), hexToBytes(s2.id), hexToBytes(a.npub)));
  assert.match(await (await fetch(`http://127.0.0.1:${b.port}/`)).text(), /Set up/);
  await new Promise((done) => b.server.close(done));
});
