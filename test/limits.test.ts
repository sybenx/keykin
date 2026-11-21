// How much the box keeps (SPEC 6, How much the box keeps): each growth limit at the limit and one over, the
// oldest going first where something goes, old state files over a limit, a blocked member staying refused,
// and that no limit stops a signature.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box, MAX_MEMBERS, MAX_CODES, OPEN_ACCOUNTS, openAccountsOf, type Account, type Member } from '../box/box.ts';
import { PageApi, MAX_SESSIONS, MAX_UNHELD_SESSIONS } from '../box/pageapi.ts';
import { startBox } from '../box/server.ts';
import { bytesToHex } from '../src/bytes.ts';

const NOW = 1_800_000_000;
const H = { connection: 'close' };
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const note = (npub: string, kind = 1) => ({ pubkey: npub, created_at: NOW, kind, tags: [], content: 'hi' });
const hashOf = (token: string) => createHash('sha256').update(token).digest('hex');
const hex = (n: number, len = 64) => n.toString(16).padStart(len, '0');
const copy = <T>(x: T): T => JSON.parse(JSON.stringify(x));

function world(open = false) {
  const box = new Box();
  let t = NOW;
  const page = new PageApi(box, () => 'https://account.example', () => open);
  const send: D.Send = async (r) => box.handle(copy(r), t);
  const call = (body: object) => page.call(copy(body), t);
  return { box, page, send, call, tick: (s: number) => { t += s; }, now: () => t };
}
type World = ReturnType<typeof world>;
async function oneAccount(w: World) {
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(w.box.qr('http://box')!), w.send, w.now());
  return { phone, held, a: w.box.only()! };
}
/** A page session made by signing in with a key, the way any site does. The box need not hold that key. */
function signin(w: World, sk = generateSecretKey()): string {
  const { challenge } = w.call({ call: 'signin_start' });
  const event = finalizeEvent({ kind: 22242, created_at: w.now(), tags: [['challenge', challenge]], content: '' }, sk);
  return w.call({ call: 'signin', event }).session;
}
/** A member standing in for a device, straight into the state: enough to fill the list. */
const filler = (a: Account, blocked: boolean, n: number): Member => ({ key: newMemberKey().key, i: a.next++, name: `Old ${n}`, kind: 'device', blocked, added: NOW, ...(blocked ? { blockedAt: NOW } : {}) });
const fill = (a: Account, upTo: number, blocked: boolean) => { for (let n = 0; a.members.length < upTo; n++) a.members.push(filler(a, blocked, n)); };
const add = (w: World, phone: D.Me, held: D.Held, m: D.Me) => D.addMember(phone, held, { key: m.key, name: m.name, kind: 'device', chip: m.chip }, w.send, w.now());
const codesOf = (b: Box) => Object.values(b.state.requests).filter((r) => r.state === 'approved' && !r.key);
const unheld = (b: Box) => Object.values(b.state.sessions ?? {}).filter((s) => !b.state.accounts[s.account]);

// ---- Members --------------------------------------------------------------------------------------------

test('members: at most 50 in an account, blocked ones included; one more is refused and nothing is dropped', async () => {
  assert.equal(MAX_MEMBERS, 50);
  const w = world();
  const { phone, held, a } = await oneAccount(w);
  fill(a, MAX_MEMBERS - 1, false);
  const tablet = device('Tablet');
  await add(w, phone, held, tablet);
  assert.equal(a.members.length, MAX_MEMBERS, 'the 50th is added');
  const th = await D.join(tablet, held.boxKey, held.npub, w.send, w.now());
  assert.ok(verifyEvent(await D.signEvent(tablet, th, note(held.npub), w.send, w.now())));
  const next = a.next, before = copy(a.members), late = device('One too many');
  const err: any = await add(w, phone, held, late).catch((e) => e);
  assert.equal(err.code, 'too_many_members');
  assert.equal(err.why, 'An account has at most 50 devices and boxes, blocked ones included. Removing blocked devices makes room.');
  assert.deepEqual(a.members, before, 'nothing dropped, nothing added');
  assert.equal(a.next, next, 'no index used up');
  assert.equal(a.welcomes[late.key], undefined);
});

test('a blocked member stays refused when the account is full, and only a cycle makes room', async () => {
  const w = world();
  const { phone, held, a } = await oneAccount(w);
  const tablet = device('Tablet');
  await add(w, phone, held, tablet);
  const th = await D.join(tablet, held.boxKey, held.npub, w.send, w.now());
  await D.block(phone, tablet.key, w.send, w.now());
  fill(a, MAX_MEMBERS, true);
  await assert.rejects(add(w, phone, held, device('New')), /too_many_members/);
  // Still refused, still listed as blocked (what a device helping with the box off reads), here and after a restart.
  await assert.rejects(D.signEvent(tablet, th, note(held.npub), w.send, w.now()), /blocked/);
  assert.equal((await D.members(phone, w.send, w.now())).members.find((m: any) => m.key === tablet.key).blocked, true);
  const again = new Box(copy(w.box.state));
  await assert.rejects(D.signEvent(tablet, th, note(held.npub), async (r) => again.handle(copy(r), w.now()), w.now()), /blocked/);
  // Removing blocked devices (the cycle) is what makes room. Nothing else drops one.
  await D.cycle(phone, held, w.send, w.now());
  assert.deepEqual(a.members.map((m) => m.name), ['Phone', 'Box']);
  await assert.rejects(D.signEvent(tablet, th, note(held.npub), w.send, w.now()), /unknown_member/);
  const laptop = device('Laptop');
  await add(w, phone, held, laptop);
  const lh = await D.join(laptop, held.boxKey, held.npub, w.send, w.now());
  assert.ok(verifyEvent(await D.signEvent(laptop, lh, note(held.npub), w.send, w.now())));
});

test('an old state already over 50 members loads, keeps every one, blocked ones refused, and takes no new one', async () => {
  const w = world();
  const { phone, held, a } = await oneAccount(w);
  const tablet = device('Tablet');
  await add(w, phone, held, tablet);
  const th = await D.join(tablet, held.boxKey, held.npub, w.send, w.now());
  await D.block(phone, tablet.key, w.send, w.now());
  fill(a, 60, false);
  const old = copy(w.box.state);
  const box = new Box(old), send: D.Send = async (r) => box.handle(copy(r), w.now());
  assert.equal(box.only()!.members.length, 60);
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), send, w.now())), 'it still signs');
  await assert.rejects(D.signEvent(tablet, th, note(held.npub), send, w.now()), /blocked/);
  await assert.rejects(D.addMember(phone, held, { key: device('x').key, name: 'x', kind: 'device' }, send, w.now()), /too_many_members/);
  assert.equal(box.only()!.members.length, 60);
});

test('moving an account in: a list of more than 50 is refused, and the account stays where it was', async () => {
  const w = world();
  await oneAccount(w);
  const code = D.readQr(w.box.newSetupCode('http://box', w.now())).code;
  const mover = device('Mover');
  const account = 'ab'.repeat(32);
  assert.equal(w.box.handle(await seal({ op: 'transfer1', request: code, account }, mover.sk, w.now()), w.now()).ok, true);
  const members = [{ key: mover.key, i: 1, name: 'Mover', kind: 'device' }, ...Array.from({ length: MAX_MEMBERS }, (_, n) => ({ key: newMemberKey().key, i: n + 3, name: `D${n}`, kind: 'device' }))];
  const r = w.box.handle(await seal({ op: 'transfer2', request: code, welcome: { npub: account, commitment: [], i: 2 }, oldBox: 'cd'.repeat(32), members }, mover.sk, w.now()), w.now());
  // The piece is checked first; a list this long is refused even before that would fail.
  assert.equal(r.error, 'too_many_members');
  assert.equal(w.box.state.accounts[account], undefined);
});

// ---- Grants and kinds -------------------------------------------------------------------------------------

test('a removed device\'s sign-ins go with it at the cycle, nothing is revoked; an old state keeping them drops them at load', async () => {
  const w = world();
  const { phone, held, a } = await oneAccount(w);
  const laptop = device('Laptop');
  await add(w, phone, held, laptop);
  const lh = await D.join(laptop, held.boxKey, held.npub, w.send, w.now());
  const mine = D.newGrant('site', 'https://mine.example', NOW), theirs = D.newGrant('site', 'https://theirs.example', NOW);
  await D.reportGrants(phone, held, [mine], w.send, w.now());
  await D.reportGrants(laptop, lh, [theirs], w.send, w.now());
  await D.block(phone, laptop.key, w.send, w.now());
  assert.deepEqual(a.grants![laptop.key].map((g) => g.id), [theirs.id], 'kept while it is only blocked');
  await D.cycle(phone, held, w.send, w.now());
  assert.equal(a.grants![laptop.key], undefined);
  assert.deepEqual(a.grants![phone.key].map((g) => g.id), [mine.id]);
  assert.deepEqual(a.revoked ?? [], [], 'nothing pushed onto the revoked list');
  // An old state from before: a removed device's grants are dropped when it loads.
  const old = copy(w.box.state);
  old.accounts[held.npub].grants![laptop.key] = [theirs];
  const again = new Box(old);
  assert.deepEqual(Object.keys(again.only()!.grants!), [phone.key]);
});

test('kinds: dropped together with their used entry at the 2000 cap; an old state with stray kinds drops them at load', async () => {
  const w = world();
  const { phone, held, a } = await oneAccount(w);
  const id = (n: number) => hex(n, 32);
  a.used = {}; a.kinds = {};
  for (let n = 0; n < 2000; n++) { a.used[id(n)] = NOW - 5000 + n; a.kinds[id(n)] = 1; }
  // At the cap: a grant already kept moves nothing.
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub, 7), w.send, w.now(), id(5))));
  assert.equal(Object.keys(a.used).length, 2000); assert.equal(Object.keys(a.kinds).length, 2000);
  assert.equal(a.kinds[id(5)], 7);
  // One more: the oldest goes from both.
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub, 6), w.send, w.now(), id(2000))));
  assert.equal(Object.keys(a.used).length, 2000); assert.equal(Object.keys(a.kinds).length, 2000);
  assert.equal(a.used[id(0)], undefined); assert.equal(a.kinds[id(0)], undefined);
  assert.equal(a.kinds[id(2000)], 6); assert.ok(a.used[id(1)]);
  // A state from before this rule, where used dropped ids and their kinds stayed: those go at load.
  const old = copy(w.box.state);
  for (let n = 0; n < 50; n++) old.accounts[held.npub].kinds![hex(n + 9000, 32)] = 1;
  const again = new Box(old).only()!;
  assert.equal(Object.keys(again.kinds!).length, 2000);
  assert.ok(Object.keys(again.kinds!).every((k) => again.used![k] !== undefined));
});

// ---- Page sessions -------------------------------------------------------------------------------------

test('page sessions for accounts this box does not hold: at most 1000 in all, the least recently used going first', async () => {
  assert.equal(MAX_UNHELD_SESSIONS, 1000);
  const w = world();
  const { phone, held } = await oneAccount(w);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw pw', w.send, w.now());
  const verifier = await D.passwordVerifier('pw pw pw pw', w.call({ call: 'pw_salt', username: 'aaron' }).salt);
  const mine = w.call({ call: 'pw_login', username: 'aaron', verifier }).session;
  const all = w.box.state.sessions!;
  for (let n = 0; n < MAX_UNHELD_SESSIONS - 1; n++) all[hashOf(`t${n}`)] = { account: hex(n + 1), how: 'scan', made: NOW, last: NOW - 5000 + n, agent: '' };
  const first = signin(w);
  assert.equal(unheld(w.box).length, MAX_UNHELD_SESSIONS, 'the 1000th is made, nothing goes');
  assert.ok(all[hashOf('t0')]);
  const second = signin(w);
  assert.equal(unheld(w.box).length, MAX_UNHELD_SESSIONS);
  assert.equal(all[hashOf('t0')], undefined, 'the least recently used went');
  assert.ok(all[hashOf('t1')]);
  for (const s of [first, second]) assert.equal(w.call({ call: 'me', session: s }).held, false);
  // A held account's sessions are not counted, and are not touched.
  assert.equal(w.call({ call: 'me', session: mine }).held, true);
});

test('an old state with more than 1000 such sessions loads, and the next sign-in brings it down to 1000', async () => {
  const w = world();
  await oneAccount(w);
  const all = w.box.state.sessions ??= {};
  for (let n = 0; n < 1100; n++) all[hashOf(`t${n}`)] = { account: hex(n + 1), how: 'scan', made: NOW, last: NOW - 5000 + n, agent: '' };
  const box = new Box(copy(w.box.state)), page = new PageApi(box, () => 'https://account.example');
  assert.equal(unheld(box).length, 1100);
  const w2 = { ...w, box, page, call: (body: object) => page.call(copy(body), NOW) } as World;
  signin(w2);
  assert.equal(unheld(box).length, 1000);
  for (let n = 0; n <= 100; n++) assert.equal(box.state.sessions![hashOf(`t${n}`)], undefined, `t${n}`);
  assert.ok(box.state.sessions![hashOf('t101')]);
});

test('an account keeps at most 100 signed-in browsers: the least recently used is signed out, and the activity says so', async () => {
  assert.equal(MAX_SESSIONS, 100);
  const w = world();
  const { phone, held } = await oneAccount(w);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw pw', w.send, w.now());
  const verifier = await D.passwordVerifier('pw pw pw pw', w.call({ call: 'pw_salt', username: 'aaron' }).salt);
  const all = w.box.state.sessions ??= {};
  for (let n = 0; n < MAX_SESSIONS - 1; n++) all[hashOf(`t${n}`)] = { account: held.npub, how: 'password', made: NOW, last: NOW - 5000 + n, agent: '' };
  const lines = () => (w.box.only()!.log ?? []).map((l) => l.text);
  w.call({ call: 'pw_login', username: 'aaron', verifier });
  assert.equal(Object.keys(all).length, MAX_SESSIONS);
  assert.ok(!lines().some((l) => /to make room/.test(l)));
  w.call({ call: 'pw_login', username: 'aaron', verifier });
  assert.equal(Object.keys(all).length, MAX_SESSIONS);
  assert.equal(all[hashOf('t0')], undefined); assert.ok(all[hashOf('t1')]);
  assert.equal(lines().filter((l) => l === 'A browser was signed out to make room: an account keeps at most 100 signed in').length, 1);
});

// ---- Setup codes and moves -----------------------------------------------------------------------------------

test('setup codes made in advance: at most 50 unused in all, the oldest going first; asks the admin approved are not counted', async () => {
  assert.equal(MAX_CODES, 50);
  const w = world();
  await oneAccount(w);
  const codes: string[] = [];
  for (let n = 0; n < MAX_CODES; n++) { codes.push(D.readQr(w.box.newSetupCode('http://box', w.now())).code); w.tick(1); }
  assert.equal(codesOf(w.box).length, MAX_CODES, 'the 50th is made, nothing goes');
  const asker = device('Asker');
  const asked = await D.askBox(asker, 'make', 'hello', w.send, w.now());
  w.box.decide(asked, true, w.now());
  codes.push(D.readQr(w.box.newSetupCode('http://box', w.now())).code);
  assert.equal(codesOf(w.box).length, MAX_CODES);
  assert.equal(w.box.state.requests[codes[0]], undefined, 'the oldest went');
  assert.equal(w.box.state.requests[asked].state, 'approved', 'the approved ask stays');
  await assert.rejects(D.createWithBox(device('Late'), { key: w.box.state.key, code: codes[0] }, w.send, w.now()), /bad_code/);
  await D.createWithBox(device('Next'), { key: w.box.state.key, code: codes[1] }, w.send, w.now());
  await D.createWithBox(asker, { key: w.box.state.key, code: asked }, w.send, w.now());
  assert.equal(w.box.accounts().length, 3);
});

test('protect: one code per signed-in account, a new one replacing the old', async () => {
  const w = world(true);
  await oneAccount(w);
  const sk = generateSecretKey(), session = signin(w, sk);
  const first = D.readQr(w.call({ call: 'protect', session }).text), second = D.readQr(w.call({ call: 'protect', session }).text);
  assert.deepEqual(codesOf(w.box).filter((r) => r.only).map((r) => r.id), [second.code]);
  const phone = device('Phone two');
  await assert.rejects(D.importWithBox(phone, first, bytesToHex(sk), w.send, w.now()), /bad_code/);
  assert.equal((await D.importWithBox(phone, second, bytesToHex(sk), w.send, w.now())).npub, getPublicKey(sk));
  // Another account's code is its own.
  const other = generateSecretKey(), os = signin(w, other);
  const o = D.readQr(w.call({ call: 'protect', session: os }).text);
  w.call({ call: 'protect', session: signin(w) });
  assert.ok(w.box.state.requests[o.code]);
});

test('an old state with more than 50 unused codes loads with all of them, and the next code brings it down to 50', async () => {
  const w = world();
  await oneAccount(w);
  const old = copy(w.box.state);
  for (let n = 0; n < 60; n++) old.requests[hex(n, 32)] = { id: hex(n, 32), what: 'make', asked: NOW + n, state: 'approved', decided: NOW + n };
  const box = new Box(old);
  assert.equal(codesOf(box).length, 60);
  box.newSetupCode('http://box', NOW + 100);
  assert.equal(codesOf(box).length, 50);
  for (let n = 0; n <= 10; n++) assert.equal(box.state.requests[hex(n, 32)], undefined);
  assert.ok(box.state.requests[hex(11, 32)]);
});

test('a move started and never finished is forgotten with its code: when it runs out, and when newer codes push it out', async () => {
  const w = world();
  await oneAccount(w);
  const mover = device('Mover');
  const start = async (code: string) => w.box.handle(await seal({ op: 'transfer1', request: code, account: 'ab'.repeat(32) }, mover.sk, w.now()), w.now());
  const one = D.readQr(w.box.newSetupCode('http://box', w.now())).code;
  assert.equal((await start(one)).ok, true);
  assert.equal(w.box.movesOpen, 1);
  w.tick(25 * 3600);
  w.box.handle(await seal({ op: 'asked', request: one }, mover.sk, w.now()), w.now());
  assert.equal(w.box.movesOpen, 0);
  const two = D.readQr(w.box.newSetupCode('http://box', w.now())).code;
  assert.equal((await start(two)).ok, true);
  assert.equal(w.box.movesOpen, 1);
  for (let n = 0; n < MAX_CODES; n++) w.box.newSetupCode('http://box', w.now());
  assert.equal(w.box.movesOpen, 0);
});

// ---- Accounts on an open box ---------------------------------------------------------------------------

test('an open box lets accounts in from the account page while it holds fewer than its cap, 500 by default; past it, box_full', async () => {
  assert.equal(OPEN_ACCOUNTS, 500);
  assert.equal(new Box().openAccounts, 500);
  for (const bad of ['-1', '1.5', 'x', '100001', '']) assert.equal(openAccountsOf(bad), null, bad);
  assert.equal(openAccountsOf(' 20 '), 20);
  assert.throws(() => new Box().setOpenAccounts(-1), /bad_number/);
  const w = world(true);
  await oneAccount(w);
  w.box.setOpenAccounts(2);
  const sk1 = generateSecretKey(), sk2 = generateSecretKey(), sk3 = generateSecretKey();
  const code1 = D.readQr(w.call({ call: 'protect', session: signin(w, sk1) }).text);
  const s2 = signin(w, sk2), code2 = D.readQr(w.call({ call: 'protect', session: s2 }).text);
  await D.importWithBox(device('One'), code1, bytesToHex(sk1), w.send, w.now());
  assert.equal(w.box.accounts().length, 2, 'the box is at its cap');
  const why = 'This box holds 2 accounts, as many as its admin lets in from the account page. Ask the admin to make room.';
  const s3 = signin(w, sk3);
  assert.deepEqual(w.call({ call: 'protect', session: s3 }), { error: 'box_full', why });
  // A code handed out before the box filled is refused when used, and kept for later.
  const err: any = await D.importWithBox(device('Two'), code2, bytesToHex(sk2), w.send, w.now()).catch((e) => e);
  assert.equal(err.code, 'box_full'); assert.equal(err.why, why);
  assert.ok(w.box.state.requests[code2.code]);
  // The admin's own codes still work: the cap is for the account page's door only.
  await D.createWithBox(device('Admin made'), D.readQr(w.box.newSetupCode('http://box', w.now())), w.send, w.now());
  assert.equal(w.box.accounts().length, 3);
  // Back to the default: the waiting code works, and the page lets people in again.
  w.box.setOpenAccounts(null);
  assert.equal(w.box.openAccounts, 500);
  assert.equal((await D.importWithBox(device('Two'), code2, bytesToHex(sk2), w.send, w.now())).npub, getPublicKey(sk2));
  assert.equal(w.call({ call: 'protect', session: s3 }).ok, true);
});

test('the open-door cap on the admin page: shown on an open box, kept in the state, overridden by KEYKIN_OPEN_ACCOUNTS', async () => {
  const d = mkdtempSync(join(tmpdir(), 'kk-open-'));
  let b: Awaited<ReturnType<typeof startBox>> | null = null;
  try {
    b = await startBox({ dir: d, port: 0, behindLogin: true, open: true, log: () => {} });
    const base = () => `http://127.0.0.1:${b!.port}`;
    const page = async () => (await fetch(base() + '/', { headers: H })).text();
    const post = (form: Record<string, string>) => fetch(base() + '/admin/openaccounts', { method: 'POST', body: new URLSearchParams(form), headers: H, redirect: 'manual' });
    const notice = async (r: Response) => decodeURIComponent(r.headers.get('location') ?? '').replace(/^\/\?n=/, '');
    const send: D.Send = async (r) => (await fetch(`${base()}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
    await D.createWithBox(device('First'), D.readQr(b.qr()!), send);
    let p = await page();
    const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(p)![1];
    assert.match(p, /Accounts from the account page/); assert.match(p, /name="accounts"[^>]*value="500"/);
    assert.match(p, /Holds now<\/span><span>1<\/span>/);
    assert.match(await notice(await post({ csrf, accounts: 'lots' })), /That is not a number from 0 to 100000/);
    assert.match(await notice(await post({ csrf, accounts: '3' })), /The account page lets accounts in while this box holds fewer than 3/);
    assert.equal(b.box.openAccounts, 3);
    await b.close(); b = null;
    b = await startBox({ dir: d, port: 0, behindLogin: true, open: true, log: () => {} });
    assert.equal(b.box.openAccounts, 3, 'kept in the state');
    await b.close(); b = null;
    b = await startBox({ dir: d, port: 0, behindLogin: true, open: true, openAccounts: '7', log: () => {} });
    assert.equal(b.box.openAccounts, 7);
    p = await page();
    assert.match(p, /Set by KEYKIN_OPEN_ACCOUNTS on this box/);
    assert.match(await notice(await post({ csrf: /name="csrf" value="([0-9a-f]+)"/.exec(p)![1], accounts: '9' })), /set by KEYKIN_OPEN_ACCOUNTS/);
    assert.equal(b.box.openAccounts, 7);
    await b.close(); b = null;
    // A box that is not open has no such card.
    b = await startBox({ dir: d, port: 0, behindLogin: true, log: () => {} });
    assert.doesNotMatch(await page(), /Accounts from the account page/);
    await b.close(); b = null;
    assert.throws(() => startBox({ dir: d, port: 0, openAccounts: 'many', log: () => {} }), /KEYKIN_OPEN_ACCOUNTS/);
  } finally { await b?.close(); rmSync(d, { recursive: true, force: true }); }
});

// ---- Signing ---------------------------------------------------------------------------------------------

test('no limit stops a signature: a box at every limit still signs and makes message keys', async () => {
  const w = world(true);
  const { phone, held, a } = await oneAccount(w);
  const tablet = device('Tablet');
  await add(w, phone, held, tablet);
  const th = await D.join(tablet, held.boxKey, held.npub, w.send, w.now());
  w.box.setOpenAccounts(1);
  fill(a, MAX_MEMBERS + 5, false);
  a.used = {}; a.kinds = {};
  for (let n = 0; n < 2000; n++) { a.used[hex(n, 32)] = NOW; a.kinds[hex(n, 32)] = 1; }
  for (let n = 0; n < MAX_CODES + 5; n++) w.box.newSetupCode('http://box', w.now());
  const all = w.box.state.sessions ??= {};
  for (let n = 0; n < MAX_UNHELD_SESSIONS + 5; n++) all[hashOf(`u${n}`)] = { account: hex(n + 1), how: 'scan', made: NOW, last: NOW, agent: '' };
  for (let n = 0; n < MAX_SESSIONS + 5; n++) all[hashOf(`h${n}`)] = { account: held.npub, how: 'password', made: NOW, last: NOW, agent: '' };
  assert.equal(w.call({ call: 'protect', session: signin(w) }).error, 'box_full');
  // Signing: with no grant, with a new grant past the cap, from both devices; and message keys.
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), w.send, w.now())));
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), w.send, w.now(), hex(5000, 32))));
  assert.ok(verifyEvent(await D.signEvent(tablet, th, note(held.npub), w.send, w.now(), hex(5001, 32))));
  const peer = getPublicKey(generateSecretKey());
  assert.equal((await D.conversationKey(phone, held, peer, w.send, w.now(), hex(5002, 32))).length, 32);
  // From a state file at every limit, too.
  const again = new Box(copy(w.box.state));
  assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), async (r) => again.handle(copy(r), w.now()), w.now(), hex(5003, 32))));
});
