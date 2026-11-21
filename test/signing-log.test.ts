// The signature log (SPEC 11.6, Recent signing): a row each time the box helps sign or make a message key,
// in signedAt order, capped, message keys folded together, and what the account page's `me` gives.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';
import { MAX_SIGNED, ECDH_SAME, SIGNED_DAYS } from '../box/signedlog.ts';
import { MemoryShelf } from '../box/lists.ts';
import { PageApi, SIGNED_SHOWN } from '../box/pageapi.ts';

const NOW = 1_800_000_000;
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const copy = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const GRANT = 'ab'.repeat(16);

async function world() {
  const box = new Box();
  let t = NOW;
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
  return { box, page, send, phone, held, note, session, tick: (s: number) => { t += s; }, now: () => t };
}

test('the box writes a row for each signature it helps with: asker, itself as helper, kind, event id, grant', async () => {
  const w = await world();
  const ev = await D.signEvent(w.phone, w.held, w.note(7), w.send, w.now(), GRANT);
  const a = { get signed() { return w.box.signedLog.rows(w.held.npub); } };
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
  const a = { get signed() { return w.box.signedLog.rows(w.held.npub); } };
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

test('at most MAX_SIGNED rows and SIGNED_DAYS, oldest going first; rows stay in signedAt order', async () => {
  const w = await world();
  const log = w.box.signedLog.rows(w.held.npub);
  // Fill straight into the log, then sign: the oldest goes.
  for (let n = 0; n < MAX_SIGNED; n++) log.push({ signedAt: NOW - 20000 + n, receivedAt: NOW, asker: w.phone.key, helper: w.box.state.key, op: 'sign', eventId: n.toString(16).padStart(64, '0') });
  // A late row (as a helper's report would be) sits at its place by signedAt.
  log.push({ signedAt: NOW + 1_000_000, receivedAt: NOW, asker: w.phone.key, helper: 'ff'.repeat(32), op: 'sign' });
  log.sort((x, y) => x.signedAt - y.signedAt);
  for (let n = 0; n < 5; n++) await D.signEvent(w.phone, w.held, w.note(), w.send, w.now());
  assert.equal(log.length, MAX_SIGNED);
  assert.equal(log[0].signedAt, NOW - 20000 + 6, 'the six oldest went');
  assert.ok(log.every((r, k) => k === 0 || log[k - 1].signedAt <= r.signedAt), 'in order');
  assert.equal(log.at(-1)!.signedAt, NOW + 1_000_000, 'the later one stays last');
  // A month on, everything older than SIGNED_DAYS goes with the next row.
  w.tick(SIGNED_DAYS * 86400 + 1);
  await D.signEvent(w.phone, w.held, w.note(), w.send, w.now());
  assert.deepEqual(log.map((r) => r.signedAt), [NOW + 1_000_000, w.now()].sort((x, y) => x - y));
});

test('the log is a file beside the state, not in it: written with the state, at most once a minute while signing', async () => {
  const w = await world();
  const shelf = new MemoryShelf();
  const { SignedLog } = await import('../box/signedlog.ts');
  w.box.signedLog = new SignedLog(shelf);
  w.tick(60);
  for (let n = 0; n < 5; n++) { await D.signEvent(w.phone, w.held, w.note(), w.send, w.now()); w.tick(5); }
  assert.equal(shelf.writes, 1, 'five signatures in one minute, one write');
  assert.equal(JSON.stringify(w.box.state).includes('signedAt'), false, 'nothing in the state file');
  assert.equal(JSON.parse(shelf.read(w.held.npub, 'signed.json')!).rows.length, 1);
  w.tick(60);
  await D.signEvent(w.phone, w.held, w.note(), w.send, w.now());
  assert.equal(JSON.parse(shelf.read(w.held.npub, 'signed.json')!).rows.length, 6);
  // A fresh log on the same shelf (a restart) reads it back.
  assert.equal(new SignedLog(shelf).rows(w.held.npub).length, 6);
  w.box.removeAccount(w.held.npub);
  assert.equal(shelf.read(w.held.npub, 'signed.json'), null, 'removing the account removes its log');
});

test('me gives the newest SIGNED_SHOWN rows, newest first, with names; a removed asker has none', async () => {
  const w = await world();
  const session = await w.session();
  await D.signEvent(w.phone, w.held, w.note(1), w.send, w.now(), GRANT);
  w.box.signedLog.rows(w.held.npub).push({ signedAt: NOW + 1, receivedAt: NOW + 1, asker: 'ee'.repeat(32), helper: w.box.state.key, op: 'ecdh' });
  const me = w.page.call({ call: 'me', session }, w.now());
  assert.ok(me.ok);
  assert.deepEqual(me.signed.map((r: any) => [r.op, r.askerName, r.helperName]), [['ecdh', null, null], ['sign', 'Phone', null], ['sign', 'Phone', null]]);
  assert.equal(me.signed[1].grant, GRANT);
  const log = w.box.signedLog.rows(w.held.npub);
  for (let n = 0; n < SIGNED_SHOWN + 50; n++) log.push({ signedAt: NOW + 10 + n, receivedAt: NOW, asker: w.phone.key, helper: w.box.state.key, op: 'sign' });
  const all = w.page.call({ call: 'me', session }, w.now()).signed;
  assert.equal(all.length, SIGNED_SHOWN);
  assert.equal(all[0].signedAt, NOW + 10 + SIGNED_SHOWN + 49);
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
