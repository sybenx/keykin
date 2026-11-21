// The box's list store (box/lists.ts, SPEC 6 "The list store"): the latest version the box signed of each kept
// list, beside state.json and never in it, so the box can compare a change with it before signing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { newMemberKey, softwareChip } from '../src/member.ts';
import { eventId } from '../src/event.ts';
import * as D from '../src/device.ts';
import { Box, keptSetsOf } from '../box/box.ts';
import { Lists, MemoryShelf, KEPT_SETS } from '../box/lists.ts';
import { startBox } from '../box/server.ts';
import { newBunker, answerRequest, errorText } from '../src/nip46.ts';
import { KeykinError } from '../src/bytes.ts';
import { main } from '../cli/keykin.ts';

const NOW = 1_800_000_000;
const pk = (i: number) => i.toString(16).padStart(64, '0');
const follows = (n: number, t = NOW) => ({ created_at: t, kind: 3, tags: Array.from({ length: n }, (_, i) => ['p', pk(i + 1)]), content: '' });
const set = (d: string, n: number, t = NOW) => ({ created_at: t, kind: 30003, tags: [['d', d], ...Array.from({ length: n }, (_, i) => ['e', pk(i + 1)])], content: '' });
const H = { connection: 'close' };

/** One account on a box reached by `send`, and signing as it: 'signed', or the error code and the box's words. */
async function account(send: D.Send, qr: string) {
  const phone: D.Me = { ...newMemberKey(), name: 'Phone', ...softwareChip() };
  const held = await D.createWithBox(phone, D.readQr(qr), send, NOW);
  const signer = (s: D.Send) => (e: any, tapped?: boolean, t = NOW) => D.signEvent(phone, held, { ...e, pubkey: held.npub }, s, t, undefined, tapped)
    .then(() => 'signed', (err) => `${err.code}${err.why ? ': ' + err.why : ''}`);
  return { phone, held, sign: signer(send), signer };
}
const local = (box: Box, t = NOW) => (async (r) => box.handle(JSON.parse(JSON.stringify(r)), t)) as D.Send;

test('the box compares with the last version it signed, and keeps only newer ones', async () => {
  const box = new Box(), shelf = box.lists.shelf as MemoryShelf;
  const a = await account(local(box), box.qr('http://box')!);
  assert.equal(await a.sign(follows(30)), 'signed');
  const writes = shelf.writes;
  assert.equal(await a.sign(follows(30)), 'signed', 'the same event again');
  assert.equal(shelf.writes, writes, 'nothing written when the list did not change');
  assert.equal(await a.sign(follows(20)), 'needs_tap: Remove 10 of your 30 follows');
  assert.equal(await a.sign(follows(20), true), 'signed');
  // Now 20 is the last version: going back to 30 is fine, and dropping 10 of those 20 is asked again.
  assert.equal(await a.sign(follows(10)), 'needs_tap: Remove 10 of your 20 follows');
  // An older version signed later is not kept as the latest.
  assert.equal(await a.sign(follows(5, NOW - 100), true), 'signed');
  assert.equal(box.lists.latest(a.held.npub, { kind: 3, tags: [] })!.tags.length, 20);
  // Lists are never in the state.
  assert.doesNotMatch(JSON.stringify(box.state), /"tags"/);
});

test('a site\'s own key (a child) is not compared, and nothing of it is kept', async () => {
  const box = new Box();
  const send = local(box);
  const a = await account(send, box.qr('http://box')!);
  const child = await D.makeChild(a.phone, a.held, 'https://site.example', send, NOW);
  const as = (e: any, tapped?: boolean) => D.signEvent(a.phone, a.held, { ...e, pubkey: child.npub }, send, NOW, undefined, tapped, child).then(() => 'signed', (err) => `${err.code}${err.why ? ': ' + err.why : ''}`);
  assert.equal(await as(follows(30)), 'signed');
  assert.equal(await as(follows(3)), 'signed', 'nothing to compare with');
  assert.equal(await as(follows(0)), 'needs_fingerprint: Empty your follow list', 'the rules that need no earlier version still speak');
  assert.equal((box.lists.shelf as MemoryShelf).names(a.held.npub).length, 0);
});

test('named sets: soft-capped per account, the least recently changed goes, it is said, and nothing is refused', async () => {
  const box = new Box();
  box.setKeptSets(2);
  let t = NOW;
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), t);
  const a = await account(send, box.qr('http://box')!);
  const sign = (e: any, tapped?: boolean) => a.signer(send)(e, tapped, t);
  assert.equal(await sign(set('one', 4)), 'signed'); t += 10;
  assert.equal(await sign(set('two', 4, t)), 'signed'); t += 10;
  assert.equal(box.lists.setCount(a.held.npub), 2);
  assert.equal(await sign(set('three', 4, t)), 'signed', 'over the cap is never refused'); t += 10;
  assert.equal(box.lists.setCount(a.held.npub), 2);
  assert.deepEqual(box.lists.uncompared(a.held.npub).map((u) => u.key), ['30003:one']);
  assert.match(box.only()!.log!.at(-1)!.text, /^Your bookmark set "one" is no longer compared before signing: this box keeps the 2 most recently changed sets$/);
  // "one" is not compared now: emptying it signs. "three" still is.
  assert.equal(await sign(set('three', 0, t)), 'needs_tap: Empty your bookmark set (it has 4 bookmarks)');
  assert.equal(await sign(set('one', 0, t)), 'signed');
  // Signing "one" kept it again, newest; "two" went in its place.
  assert.deepEqual(box.lists.uncompared(a.held.npub).map((u) => u.key), ['30003:two']);
  // Replaceable lists have no cap.
  for (const k of [10000, 10001, 10002, 10003]) assert.equal(await sign({ created_at: t, kind: k, tags: [], content: '' }), 'signed');
  assert.equal(box.lists.setCount(a.held.npub), 2);
  // A cap of 0 keeps no set and says nothing about one never kept.
  box.setKeptSets(0);
  const lines = box.only()!.log!.length;
  t += 10; assert.equal(await sign(set('four', 3, t)), 'signed');
  assert.equal(box.lists.setCount(a.held.npub), 0);
  assert.ok(box.only()!.log!.slice(lines).every((l) => !/"four"/.test(l.text)));
});

test('the cap: 200 by default, set on the admin page, overridden by KEYKIN_KEPT_SETS', async () => {
  assert.equal(KEPT_SETS, 200);
  assert.equal(new Box().keptSets, 200);
  for (const bad of ['-1', '1.5', 'x', '100001', '']) assert.equal(keptSetsOf(bad), null, bad);
  assert.equal(keptSetsOf(' 50 '), 50);
  assert.throws(() => new Box().setKeptSets(-1), /bad_number/);
  const d = mkdtempSync(join(tmpdir(), 'kk-kept-'));
  try {
    let b = await startBox({ dir: d, port: 0, behindLogin: true, log: () => {} });
    const base = () => `http://127.0.0.1:${b.port}`;
    const page = async () => (await fetch(base() + '/', { headers: H })).text();
    const post = (form: Record<string, string>) => fetch(base() + '/admin/keptsets', { method: 'POST', body: new URLSearchParams(form), headers: H, redirect: 'manual' });
    const notice = async (r: Response) => decodeURIComponent(r.headers.get('location') ?? '').replace(/^\/\?n=/, '');
    const send: D.Send = async (r) => (await fetch(`${base()}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
    await D.createWithBox({ ...newMemberKey(), name: 'First', ...softwareChip() }, D.readQr(b.qr()!), send);
    let p = await page();
    const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(p)![1];
    assert.match(p, /Lists the box compares/); assert.match(p, /name="sets"[^>]*value="200"/);
    assert.match(await notice(await post({ csrf, sets: 'lots' })), /That is not a number from 0 to 100000/);
    assert.match(await notice(await post({ csrf, sets: '50' })), /The box compares the 50 most recently changed sets of each account/);
    assert.equal(b.box.keptSets, 50);
    await b.close();
    b = await startBox({ dir: d, port: 0, behindLogin: true, log: () => {} });
    assert.equal(b.box.keptSets, 50, 'kept in the state');
    await b.close();
    b = await startBox({ dir: d, port: 0, behindLogin: true, keptSets: '7', log: () => {} });
    assert.equal(b.box.keptSets, 7);
    p = await page();
    assert.match(p, /Set by KEYKIN_KEPT_SETS on this box/);
    assert.match(await notice(await post({ csrf: /name="csrf" value="([0-9a-f]+)"/.exec(p)![1], sets: '9' })), /set by KEYKIN_KEPT_SETS/);
    assert.equal(b.box.keptSets, 7);
    await b.close();
    assert.throws(() => startBox({ dir: d, port: 0, keptSets: 'many', log: () => {} }), /KEYKIN_KEPT_SETS/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('on disk: one file per list beside state.json, read again after a restart, gone with its account', async () => {
  const d = mkdtempSync(join(tmpdir(), 'kk-lists-'));
  try {
    let b = await startBox({ dir: d, port: 0, log: () => {} });
    const a = await account(local(b.box), b.qr()!);
    assert.equal(await a.sign(follows(30)), 'signed');
    assert.equal(await a.sign(set('reading', 4)), 'signed');
    await b.close();
    assert.doesNotMatch(readFileSync(join(d, 'state.json'), 'utf8'), /"tags"/, 'no list in state.json');
    const mine = join(d, 'lists', a.held.npub);
    assert.deepEqual(readdirSync(mine).sort(), ['3.json', `30003-${(await import('../src/bytes.ts')).shaHex('reading').slice(0, 32)}.json`, 'sets.json'].sort());
    const f = JSON.parse(readFileSync(join(mine, '3.json'), 'utf8'));
    assert.equal(f.key, '3'); assert.equal(f.at, NOW); assert.equal(f.event.tags.length, 30);
    assert.equal(f.event.id, eventId({ ...follows(30), pubkey: a.held.npub }));
    b = await startBox({ dir: d, port: 0, log: () => {} });
    assert.equal(await a.signer(local(b.box))(follows(0)), 'needs_fingerprint: Empty your follow list (it has 30 follows)', 'compared after a restart');
    b.box.removeAccount(a.held.npub);
    assert.equal(existsSync(mine), false, 'its lists go with it');
    await b.close();
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('an old box with no list store keeps working, and lists of accounts no longer here are tidied at start', async () => {
  const d = mkdtempSync(join(tmpdir(), 'kk-old-'));
  try {
    let b = await startBox({ dir: d, port: 0, log: () => {} });
    const a = await account(local(b.box), b.qr()!);
    assert.equal(await a.sign(follows(30)), 'signed');
    await b.close();
    rmSync(join(d, 'lists'), { recursive: true });              // as a box from before the list store
    b = await startBox({ dir: d, port: 0, log: () => {} });
    const sign = a.signer(local(b.box));
    assert.equal(await sign(follows(3)), 'signed', 'nothing to compare with, as on a new phone');
    assert.equal(await sign(follows(0)), 'needs_fingerprint: Empty your follow list (it has 3 follows)', 'and from then on it compares');
    // A folder for an account this box does not hold goes at the next start.
    new Lists(new (await import('../box/lists.ts')).DiskShelf(join(d, 'lists'))).keep('ab'.repeat(32), { ...follows(2), pubkey: 'ab'.repeat(32), id: 'x' }, 200, NOW);
    await b.close();
    b = await startBox({ dir: d, port: 0, log: () => {} });
    assert.deepEqual(readdirSync(join(d, 'lists')), [a.held.npub]);
    await b.close();
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('needs_tap, needs_fingerprint and dated_ahead carry the reason as why, the bunker and the command line say it, other errors carry none', async () => {
  const box = new Box();
  const a = await account(local(box), box.qr('http://box')!);
  const five = { created_at: NOW, kind: 5, tags: Array.from({ length: 5 }, (_, i) => ['e', pk(i + 1)]), content: '' };
  assert.equal(await a.sign(five), 'needs_tap: Delete 5 of your events');
  // The error itself: code, message and why.
  const err: any = await D.signEvent(a.phone, a.held, { ...five, pubkey: a.held.npub }, local(box), NOW).catch((e) => e);
  assert.equal(err.code, 'needs_tap'); assert.equal(err.why, 'Delete 5 of your events');
  assert.equal(err.message, 'needs_tap: Delete 5 of your events');
  // Level 2 carries its words the same way, under its own code, and tapped does not sign it.
  const vanish = { created_at: NOW, kind: 62, tags: [['relay', 'ALL_RELAYS']], content: '' };
  assert.equal(await a.sign(vanish, true), 'needs_fingerprint: Ask relays to erase everything you have ever published');
  const two: any = await D.signEvent(a.phone, a.held, { ...vanish, pubkey: a.held.npub }, local(box), NOW, undefined, true).catch((e) => e);
  assert.equal(two.code, 'needs_fingerprint'); assert.equal(two.why, 'Ask relays to erase everything you have ever published');
  // Dated ahead is refused whatever the person says.
  assert.equal(await a.sign({ ...follows(3), created_at: NOW + 3600 }, true), 'dated_ahead: Follow list dated 2027-01-15: a version dated ahead would block every later change');
  // An ordinary error has no why.
  const plain: any = await D.signEvent(a.phone, a.held, { ...follows(1), pubkey: 'ab'.repeat(32) }, local(box), NOW).catch((e) => e);
  assert.equal(plain.code, 'wrong_account'); assert.equal(plain.why, undefined);
  // The bunker, which cannot ask: a site that asks it to sign gets the box's words, not a bare code, and for level 2
  // that it is done from the phone.
  const b = newBunker(); b.clients.push('cd'.repeat(32));
  const real = () => Math.floor(Date.now() / 1000);       // the bunker signs at the time it is
  const viaBunker = (e: object) => answerRequest(b, a.phone, a.held, (async (r) => box.handle(JSON.parse(JSON.stringify(r)), real())) as D.Send, 'cd'.repeat(32), 'sign_event',
    [JSON.stringify({ created_at: real(), content: '', ...e })], () => {}).then(() => 'signed', errorText);
  assert.equal(await viaBunker({ kind: 5, tags: five.tags }), 'needs_tap: Delete 5 of your events');
  assert.equal(await viaBunker({ kind: 3, tags: [] }), 'needs_fingerprint: Empty your follow list. Do this from your phone.');
  assert.equal(errorText(plain), 'wrong_account'); assert.equal(errorText(new Error('x')), 'failed');
  // An account change's needs_fingerprint has no words, and is said as before.
  assert.equal(errorText(new KeykinError('needs_fingerprint')), 'needs_fingerprint');
  assert.equal(errorText(new KeykinError('no_chip_key', 'Empty your follow list', 'Empty your follow list')), 'no_chip_key: Empty your follow list. Do this from your phone.');
  // The command-line device prints the error's message, which is the same words.
  assert.match(String(err.message), /^needs_tap: Delete 5/);
});

test('the command line never signs level 2, and says in plain words that it is done from the phone', async () => {
  const b = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-l2-box-')), port: 0, log: () => {} });
  const home = mkdtempSync(join(tmpdir(), 'kk-l2-cli-'));
  try {
    const lines: string[] = [];
    await main(['create', b.qr()!, 'Laptop', '--username', 'leveltwo', '--password', 'long enough pw'], (x) => lines.push(x), home);
    const sign = (e: object) => main(['sign', JSON.stringify(e)], () => {}, home).then(() => 'signed', (err) => String(err?.message ?? err));
    assert.equal(await sign({ kind: 62, tags: [['relay', 'ALL_RELAYS']] }), 'Not signed: Ask relays to erase everything you have ever published. Do this from your phone.');
    assert.equal(await sign({ kind: 3, tags: [] }), 'Not signed: Empty your follow list. Do this from your phone.');
    // Level 1 is as before: the box's words with its code.
    assert.equal(await sign({ kind: 5, tags: Array.from({ length: 5 }, (_, i) => ['e', pk(i + 1)]) }), 'needs_tap: Delete 5 of your events');
    assert.equal(await sign({ kind: 1, content: 'gm' }), 'signed');
  } finally { await b.close(); rmSync(home, { recursive: true, force: true }); }
});
