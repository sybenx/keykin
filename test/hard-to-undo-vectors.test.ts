// vectors/hard-to-undo.json, the shared hard-to-undo cases, against src/destructive.ts and against the box that
// enforces it. src/destructive.ts must give the keykin answer in every case, and the box must refuse exactly those
// events with needs_tap unless the device says it asked. Marble's answers in the file are held by Marble's own test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { destructive } from '../src/destructive.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';

const V = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/hard-to-undo.json'), 'utf8'));
const { build } = await import('../tools/hard-to-undo-vectors.mjs' as string);
const IMPLS = ['keykin', 'marble', 'marble-keykin-copy'];
const label = (c: any) => `${c.why} (${JSON.stringify(c.event).slice(0, 120)})`;

test('hard-to-undo vectors: the file is what the tool makes', () => {
  assert.deepEqual(V, JSON.parse(JSON.stringify(build())), 'run node tools/hard-to-undo-vectors.mjs, then copy it to Marble');
});

test('hard-to-undo vectors: each case is whole, and expect is only set where all agree', () => {
  const ids = new Set(V.rules.map((r: any) => r.id));
  for (const c of V.cases) {
    assert.deepEqual(Object.keys(c.answers).sort(), [...IMPLS].sort(), label(c));
    for (const a of Object.values(c.answers) as any[]) {
      assert.ok(['sign', 'ask', 'refuse'].includes(a.decision), label(c));
      assert.equal(a.says === null, a.decision === 'sign', label(c));
    }
    const ds = new Set(Object.values(c.answers).map((a: any) => a.decision));
    assert.equal(c.expect, ds.size === 1 ? [...ds][0] : 'undecided', label(c));
    if (c.uncaught) assert.equal(c.expect, 'sign', `${label(c)}: uncaught means nobody asks`);
    for (const r of c.rules) assert.ok(ids.has(r), `${label(c)}: unknown rule ${r}`);
  }
  // Every rule of every implementation is met by a case where that implementation does not sign.
  for (const r of V.rules) for (const impl of r.impl) {
    assert.ok(V.cases.some((c: any) => c.rules.includes(r.id) && c.answers[impl].decision !== 'sign'), `${r.id}: no case where ${impl} catches it`);
  }
});

test('hard-to-undo vectors: src/destructive.ts gives the keykin answer', () => {
  for (const c of V.cases) {
    const says = destructive(c.event);
    assert.deepEqual({ decision: says ? 'ask' : 'sign', says }, c.answers.keykin, label(c));
  }
});

test('hard-to-undo vectors: the box refuses exactly those without tapped, and signs them with it', async () => {
  const box = new Box();
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), V.now);
  const phone: D.Me = { ...newMemberKey(), name: 'Phone', ...softwareChip() };
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, V.now);
  for (const c of V.cases) {
    const e = { ...c.event, pubkey: held.npub };
    const plain = await D.signEvent(phone, held, e, send, V.now).then(() => 'signed', (err) => err.code ?? err.message);
    assert.equal(plain, c.answers.keykin.decision === 'ask' ? 'needs_tap' : 'signed', label(c));
    if (c.answers.keykin.decision === 'ask') assert.ok((await D.signEvent(phone, held, e, send, V.now, undefined, true)).sig, label(c));
  }
});
