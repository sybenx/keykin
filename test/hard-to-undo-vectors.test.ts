// vectors/hard-to-undo.json, the shared hard-to-undo cases, against src/destructive.ts and against the box that
// enforces it. src/destructive.ts must give the box answer in every case, and the box must answer it over the wire:
// `needs_tap` with the words as `why` unless the device says it asked, `dated_ahead` with the words always. Where a
// case has an earlier version, the box learns it the only way it can: by signing it first. Marble's answers in the
// file are held by Marble's own test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { judge } from '../src/destructive.ts';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import { ask as commitTo } from '../src/round.ts';
import { eventId } from '../src/event.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';

const V = JSON.parse(readFileSync(join(import.meta.dirname, '../vectors/hard-to-undo.json'), 'utf8'));
const { build } = await import('../tools/hard-to-undo-vectors.mjs' as string);
const IMPLS = ['box', 'marble'];
const label = (c: any) => `${c.why} (${JSON.stringify(c.event).slice(0, 120)})`;

test('hard-to-undo vectors: the file is what the tool makes', () => {
  assert.deepEqual(V, JSON.parse(JSON.stringify(build())), 'run node tools/hard-to-undo-vectors.mjs, then copy it to Marble');
});

test('hard-to-undo vectors: each case is whole, and expect is the box', () => {
  const ids = new Set(V.rules.map((r: any) => r.id));
  for (const c of V.cases) {
    assert.deepEqual(Object.keys(c.answers).sort(), [...IMPLS].sort(), label(c));
    for (const a of Object.values(c.answers) as any[]) {
      assert.ok(['sign', 'ask', 'refuse'].includes(a.decision), label(c));
      assert.equal(a.says === null, a.decision === 'sign', label(c));
    }
    assert.equal(c.expect, c.answers.box.decision, label(c));
    // The box has Marble's rules: wherever Marble does not sign, the box answers the same, in the same words.
    if (c.answers.marble.decision !== 'sign') assert.deepEqual(c.answers.box, c.answers.marble, label(c));
    if (c.uncaught) assert.equal(c.expect, 'sign', `${label(c)}: uncaught means nobody asks`);
    for (const r of c.rules) assert.ok(ids.has(r), `${label(c)}: unknown rule ${r}`);
  }
  // Every rule of every implementation is met by a case where that implementation does not sign.
  for (const r of V.rules) for (const impl of r.impl) {
    assert.ok(V.cases.some((c: any) => c.rules.includes(r.id) && c.answers[impl].decision !== 'sign'), `${r.id}: no case where ${impl} catches it`);
  }
});

test('hard-to-undo vectors: src/destructive.ts gives the box answer', () => {
  for (const c of V.cases) assert.deepEqual(judge(c.event, c.prev, V.now), c.answers.box, label(c));
});

/** A fresh account on `box`, and a way to sign as it with or without `tapped`, answering 'signed' or the error with its why. */
async function account(box: Box) {
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), V.now);
  const phone: D.Me = { ...newMemberKey(), name: 'Phone', ...softwareChip() };
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box') ?? box.newSetupCode('http://box', V.now)), send, V.now);
  const sign = (e: any, tapped?: boolean) => D.signEvent(phone, held, { ...e, pubkey: held.npub }, send, V.now, undefined, tapped)
    .then((x) => (assert.ok(x.sig), 'signed'), (err) => `${err.code}${err.why ? ': ' + err.why : ''}`);
  // The raw answer, to see the field itself.
  const raw = async (e: any, tapped?: boolean) => {
    const ev = { ...e, pubkey: held.npub };
    return send(await seal({ op: 'sign', event: ev, commit: commitTo(held.piece, eventId(ev)).commit, tapped, epoch: held.epoch, account: held.npub }, phone.sk, V.now));
  };
  return { held, sign, raw };
}
const wanted = (a: any, tapped: boolean) => a.decision === 'refuse' ? `dated_ahead: ${a.says}` : a.decision === 'ask' && !tapped ? `needs_tap: ${a.says}` : 'signed';

test('hard-to-undo vectors: the box answers every case, with the earlier version it signed, and with tapped', async () => {
  for (const c of V.cases) {
    const { sign, raw } = await account(new Box());
    // The earlier version reaches the box the way it would: the box signs it (a Yes given, if it asks).
    if (c.prev) assert.equal(await sign(c.prev, true), 'signed', `${label(c)}: its earlier version`);
    const r = await raw(c.event);
    const b = c.answers.box;
    if (b.decision === 'sign') assert.equal(r.ok, true, label(c));
    else assert.deepEqual({ error: r.error, why: r.why }, { error: b.decision === 'ask' ? 'needs_tap' : 'dated_ahead', why: b.says }, label(c));
    assert.equal(await sign(c.event, true), wanted(b, true), `${label(c)}: tapped`);
  }
});

test('hard-to-undo vectors: without an earlier version, only the rules that need none speak', async () => {
  const box = new Box();
  for (const c of V.cases.filter((x: any) => x.prev)) {
    const { sign } = await account(box);
    const alone = V.cases.find((x: any) => !x.prev && JSON.stringify(x.event) === JSON.stringify(c.event));
    const got = await sign(c.event);
    // The same event with no earlier version is a case of its own where the file has one; otherwise the answer is
    // never more than with one (no rule asks only because nothing came before), and refusals do not depend on it.
    if (alone) assert.equal(got, wanted(alone.answers.box, false), label(c));
    else if (c.answers.box.decision === 'refuse') assert.equal(got, wanted(c.answers.box, false), label(c));
    else if (c.answers.box.decision === 'sign') assert.equal(got, 'signed', label(c));
  }
});
