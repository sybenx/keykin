// The signature log (SPEC 11.6, Recent signing): a row each time the box helps sign or make a message key,
// in signedAt order, capped, message keys folded together, and what the account page's `me` gives.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box, MAX_SIGNED, ECDH_SAME } from '../box/box.ts';
import { PageApi } from '../box/pageapi.ts';

const NOW = 1_800_000_000;
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const copy = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const GRANT = 'ab'.repeat(16);

async function world() {
  const box = new Box();
  let t = NOW, saves = 0;
  box.onChange = () => { saves++; };
  const page = new PageApi(box, () => 'https://account.example', () => false);
  const send: D.Send = async (r) => box.handle(copy(r), t);
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, t);
  const note = (kind = 1) => ({ pubkey: held.npub, created_at: t, kind, tags: [], content: 'hi ' + Math.random() });
  // A page session for the account itself: sign the page's challenge with the account's own pieces.
  const session = async () => {
    const { challenge } = page.call({ call: 'signin_start' }, t);
    const event = await D.signEvent(phone, held, { pubkey: held.npub, created_at: t, kind: 22242, tags: [['challenge', challenge]], content: '' }, send, t);
    return page.call({ call: 'signin', event }, t).session as string;
  };
  return { box, page, send, phone, held, note, session, tick: (s: number) => { t += s; }, now: () => t, saves: () => saves };
}

test('the box writes a row for each signature it helps with: asker, itself as helper, kind, event id, grant', async () => {
  const w = await world();
  const ev = await D.signEvent(w.phone, w.held, w.note(7), w.send, w.now(), GRANT);
  const a = w.box.only()!;
  assert.deepEqual(a.signed, [{ signedAt: NOW, receivedAt: NOW, asker: w.phone.key, helper: w.box.state.key, op: 'sign', kind: 7, eventId: ev.id, grant: GRANT }]);
  // No grant, no grant field.
  w.tick(5);
  await D.signEvent(w.phone, w.held, w.note(1), w.send, w.now());
  assert.equal(a.signed!.length, 2);
  assert.equal('grant' in a.signed![1], false);
  assert.equal(a.signed![1].signedAt, NOW + 5);
});

test('message keys: one row, no kind or event id, and close repeats fold into the latest', async () => {
  const w = await world();
  const peer = getPublicKey(generateSecretKey());
  await D.conversationKey(w.phone, w.held, peer, w.send, w.now(), GRANT);
  const a = w.box.only()!;
  assert.deepEqual(a.signed, [{ signedAt: NOW, receivedAt: NOW, asker: w.phone.key, helper: w.box.state.key, op: 'ecdh', grant: GRANT }]);
  w.tick(30);
  await D.conversationKey(w.phone, w.held, peer, w.send, w.now(), GRANT);
  assert.equal(a.signed!.length, 1, 'folded');
  assert.equal(a.signed![0].signedAt, NOW + 30);
  // A signature in between does not stop the fold, and stays.
  await D.signEvent(w.phone, w.held, w.note(), w.send, w.now());
  w.tick(30);
  await D.conversationKey(w.phone, w.held, peer, w.send, w.now(), GRANT);
  assert.deepEqual(a.signed!.map((r) => r.op), ['sign', 'ecdh']);
  // Another grant is its own row; so is the same grant after the window.
  await D.conversationKey(w.phone, w.held, peer, w.send, w.now(), 'cd'.repeat(16));
  w.tick(ECDH_SAME);
  await D.conversationKey(w.phone, w.held, peer, w.send, w.now(), GRANT);
  assert.deepEqual(a.signed!.map((r) => r.op), ['sign', 'ecdh', 'ecdh', 'ecdh']);
});

test('at most MAX_SIGNED rows, oldest going first; rows stay in signedAt order; saves stay at most once a minute', async () => {
  const w = await world();
  const a = w.box.only()!;
  // Fill straight into the state, then sign: the oldest goes.
  a.signed = Array.from({ length: MAX_SIGNED }, (_, n) => ({ signedAt: NOW - 1000 + n, receivedAt: NOW, asker: w.phone.key, helper: w.box.state.key, op: 'sign' as const, eventId: n.toString(16).padStart(64, '0') }));
  // A late row (as a helper's report would be) goes in its place by signedAt.
  a.signed.splice(10, 0, { signedAt: NOW + 3600, receivedAt: NOW, asker: w.phone.key, helper: 'ff'.repeat(32), op: 'sign' });
  a.signed.sort((x, y) => x.signedAt - y.signedAt);
  w.tick(60);
  const before = w.saves();
  for (let n = 0; n < 5; n++) await D.signEvent(w.phone, w.held, w.note(), w.send, w.now());
  assert.equal(a.signed.length, MAX_SIGNED);
  assert.equal(a.signed[0].signedAt, NOW - 1000 + 6, 'the six oldest went');
  assert.ok(a.signed.every((r, k) => k === 0 || a.signed![k - 1].signedAt <= r.signedAt), 'in order');
  assert.equal(a.signed.at(-1)!.signedAt, NOW + 3600, 'the later one stays last');
  assert.ok(w.saves() - before <= 1, 'five signatures in one minute, at most one save');
});

test('me gives the log newest first with names; a removed asker has none', async () => {
  const w = await world();
  const session = await w.session();
  await D.signEvent(w.phone, w.held, w.note(1), w.send, w.now(), GRANT);
  const a = w.box.only()!;
  a.signed!.push({ signedAt: NOW + 1, receivedAt: NOW + 1, asker: 'ee'.repeat(32), helper: w.box.state.key, op: 'ecdh' });
  const me = w.page.call({ call: 'me', session }, w.now());
  assert.ok(me.ok);
  assert.deepEqual(me.signed.map((r: any) => [r.op, r.askerName, r.helperName]), [['ecdh', null, null], ['sign', 'Phone', null], ['sign', 'Phone', null]]);
  assert.equal(me.signed[1].grant, GRANT);
});

test('the Recent signing line', async () => {
  // @ts-ignore: a plain script for the page
  await import('../login/static/rows.js');
  const { signedRow } = (globalThis as any).KeykinRows;
  const box = 'bb'.repeat(32), grants = [{ id: GRANT, name: 'https://jumble.social' }];
  const r = { signedAt: NOW, asker: 'aa'.repeat(32), askerName: 'Pixel 9a', helper: box, helperName: null, op: 'sign', kind: 7, eventId: '1a2b3c4d'.padEnd(64, '0'), grant: GRANT };
  assert.deepEqual(signedRow(r, box, grants, NOW + 120), { who: 'Pixel 9a + your box', detail: 'Signed a reaction for jumble.social · 2 min ago · event 1a2b3c4d…' });
  assert.deepEqual(signedRow({ ...r, op: 'ecdh', kind: undefined, eventId: undefined, grant: 'cd'.repeat(16), askerName: null }, box, grants, NOW),
    { who: 'A removed device + your box', detail: 'Made a message key for a site that was signed out · a minute ago' });
  assert.equal(signedRow({ ...r, kind: 30023, grant: undefined }, box, [], NOW).detail, 'Signed an article · a minute ago · event 1a2b3c4d…');
  assert.equal(signedRow({ ...r, helper: 'cc'.repeat(32), helperName: 'Laptop' }, box, grants, NOW).who, 'Pixel 9a + Laptop');
});
