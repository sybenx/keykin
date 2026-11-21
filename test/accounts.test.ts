// Many accounts on one box, asking and approving, and what the account page may do (SPEC 11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';
import { PageApi } from '../box/pageapi.ts';
import { eventId } from '../src/event.ts';
import { hexToBytes, bytesToHex, randomBytes, sha } from '../src/bytes.ts';
import { newBunker, bunkerTicket, answerRequest, syncGrants } from '../src/nip46.ts';
import { getPublicKey } from 'nostr-tools/pure';
const schnorrSha = (v: string) => sha(new TextEncoder().encode(v));

const NOW = 1_800_000_000;
const device = (name: string, chip = true): D.Me => ({ ...newMemberKey(), name, ...(chip ? softwareChip() : {}) });
const note = (npub: string, content = 'hello') => ({ pubkey: npub, created_at: NOW, kind: 1, tags: [], content });
const valid = (ev: { sig: string; id: string; pubkey: string }) => schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));

function world() {
  const box = new Box();
  const page = new PageApi(box, () => 'https://account.example');
  let t = NOW;
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), t);
  const call = (body: object) => page.call(JSON.parse(JSON.stringify(body)), t);
  return { box, page, send, call, tick: (s: number) => { t += s; }, now: () => t };
}

test('a box holds many accounts; each request names its own', async () => {
  const { box, send } = world();
  const alice = device('Alice phone'), bob = device('Bob phone');
  const a = await D.createWithBox(alice, D.readQr(box.qr('http://box')!), send, NOW);
  assert.equal(box.qr('http://box'), null);                                   // the first-run code is spent
  // A second account needs a code the admin made.
  const b = await D.createWithBox(bob, D.readQr(box.newSetupCode('http://box', NOW)), send, NOW);
  assert.notEqual(a.npub, b.npub);
  assert.deepEqual(box.accounts().map((x) => x.npub), [a.npub, b.npub]);
  // Each signs under its own key, and neither is known in the other's account.
  assert.ok(valid(await D.signEvent(alice, a, note(a.npub), send, NOW)));
  assert.ok(valid(await D.signEvent(bob, b, note(b.npub), send, NOW)));
  assert.deepEqual(box.handle(await seal({ op: 'members', account: b.npub }, alice.sk, NOW), NOW), { error: 'unknown_member' });
  // With two accounts a request must say which; an older device that names none is told so.
  assert.deepEqual(box.handle(await seal({ op: 'members' }, alice.sk, NOW), NOW), { error: 'need_account' });
  assert.deepEqual(box.handle(await seal({ op: 'members', account: 'f'.repeat(64) }, alice.sk, NOW), NOW), { error: 'unknown_account' });
  assert.equal((await D.members(alice, send, NOW, a.npub)).members.length, 2);
  // Blocking in one account touches nothing in the other.
  const laptop = device('Alice laptop');
  await D.addMember(alice, a, { key: laptop.key, name: laptop.name, kind: 'device', chip: laptop.chip }, send, NOW);
  await D.block(alice, laptop.key, send, NOW, a.npub);
  await D.cycle(alice, a, send, NOW);
  assert.ok(valid(await D.signEvent(bob, b, note(b.npub), send, NOW)));
  // The admin removes one; the other carries on.
  box.removeAccount(a.npub);
  await assert.rejects(D.signEvent(alice, a, note(a.npub), send, NOW), /unknown_account/);
  assert.ok(valid(await D.signEvent(bob, b, note(b.npub), send, NOW)));
});

test('a state file from a one-account box still loads, and old devices still work on it', async () => {
  const { box, send } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  const old: any = JSON.parse(JSON.stringify(box.state));
  old.account = old.accounts[held.npub]; delete old.accounts; delete old.requests;       // how it used to be saved
  const again = new Box(old);
  assert.equal(again.only()!.npub, held.npub);
  // A request with no `account`, as an older app sends it.
  const mine = eventId(note(held.npub));
  assert.equal(again.handle(await seal({ op: 'members' }, phone.sk, NOW), NOW).npub, held.npub);
  assert.ok(mine);
});

test('asking for an account waits for the admin', async () => {
  const { box, send } = world();
  await D.createWithBox(device('First'), D.readQr(box.qr('http://box')!), send, NOW);
  const carol = device('Carol phone');
  const id = await D.askBox(carol, 'make', "Carol, Aaron's sister", send, NOW);
  assert.equal(await D.askBox(carol, 'make', 'again', send, NOW), id);         // one waiting request per device
  assert.equal(await D.asked(carol, id, send, NOW), 'waiting');
  assert.deepEqual(await D.askedWithKey(carol, id, send, NOW), { state: 'waiting', key: box.state.key });    // all a phone with only an address needs
  await assert.rejects(D.createWithBox(carol, { key: box.state.key, code: id }, send, NOW), /not_approved/);
  // What the admin sees.
  const r = box.state.requests[id];
  assert.deepEqual([r.what, r.name, r.note, r.key, r.state], ['make', 'Carol phone', "Carol, Aaron's sister", carol.key, 'waiting']);
  // Someone else cannot use Carol's request, even once approved.
  box.decide(id, true, NOW);
  assert.equal(await D.asked(carol, id, send, NOW), 'approved');
  await assert.rejects(D.createWithBox(device('Mallory'), { key: box.state.key, code: id }, send, NOW), /bad_code/);
  const held = await D.createWithBox(carol, { key: box.state.key, code: id }, send, NOW);
  assert.ok(valid(await D.signEvent(carol, held, note(held.npub), send, NOW)));
  assert.equal(await D.asked(carol, id, send, NOW), 'gone');                   // used up
  // A refusal, and a request nobody answered.
  const dave = device('Dave');
  const id2 = await D.askBox(dave, 'make', '', send, NOW);
  box.decide(id2, false, NOW);
  await assert.rejects(D.createWithBox(dave, { key: box.state.key, code: id2 }, send, NOW), /refused/);
  // Taking a request back: only the one who asked can.
  const frank = device('Frank');
  const id4 = await D.askBox(frank, 'make', '', send, NOW);
  await assert.rejects(D.askCancel(dave, id4, send, NOW), /gone/);
  await D.askCancel(frank, id4, send, NOW);
  assert.equal(await D.asked(frank, id4, send, NOW), 'gone');
  assert.equal(box.state.requests[id4], undefined);
  const eve = device('Eve');
  const id3 = await D.askBox(eve, 'make', '', send, NOW);
  assert.equal(box.handle(await seal({ op: 'asked', request: id3 }, eve.sk, NOW + 8 * 86400), NOW + 8 * 86400).state, 'gone');
});

test('the account page: password login, its limits, and what it may and may not do', async () => {
  const { box, send, call, tick, now } = world();
  const phone = device('Phone'), laptop = device('Laptop');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, send, NOW);

  // Setting a password needs the fingerprint, and the box never gets the password.
  await assert.rejects(D.passwordSet({ ...phone, fp: undefined }, held, 'aaron', 'correct horse', send, NOW), /needs_fingerprint/);
  await assert.rejects(D.passwordSet(phone, held, 'A', 'x', send, NOW), /bad_username/);
  assert.equal((await D.members(phone, send, NOW, held.npub)).password, false);   // devices can tell an account has none yet
  await D.passwordSet(phone, held, 'aaron', 'correct horse', send, NOW);
  assert.doesNotMatch(JSON.stringify(box.state), /correct horse/);
  assert.equal((await D.members(phone, send, NOW, held.npub)).password, true);

  // Logging in: the page fetches the salt, makes the verifier itself, and sends that.
  const { salt } = call({ call: 'pw_salt', username: 'aaron' });
  assert.equal(call({ call: 'pw_salt', username: 'nobody' }).salt, call({ call: 'pw_salt', username: 'nobody' }).salt);   // gives nothing away
  assert.notEqual(call({ call: 'pw_salt', username: 'nobody' }).salt, salt);
  const good = await D.passwordVerifier('correct horse', salt), bad = await D.passwordVerifier('wrong', salt);
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: bad }), { error: 'wrong' });
  assert.deepEqual(call({ call: 'pw_login', username: 'nobody', verifier: bad }), { error: 'wrong' });
  const { session } = call({ call: 'pw_login', username: 'aaron', verifier: good });
  assert.match(session, /^[0-9a-f]{64}$/);

  // What a session sees.
  const me = call({ call: 'me', session });
  assert.equal(me.npub, held.npub); assert.equal(me.username, 'aaron');
  assert.deepEqual(me.devices.map((d: any) => [d.name, d.kind, d.blocked, d.fingerprint]), [['Phone', 'device', false, true], ['Box', 'box', false, false], ['Laptop', 'device', false, true]]);
  assert.deepEqual(call({ call: 'me', session: 'f'.repeat(64) }), { error: 'login' });

  // A signed-in page blocks and unblocks. It has no call that signs or hands over a key or a piece.
  assert.deepEqual(call({ call: 'block', session, key: laptop.key }), { ok: true });
  await assert.rejects(D.signEvent(laptop, lh, note(held.npub), send, NOW), /blocked/);
  assert.equal(call({ call: 'me', session }).how, 'password');
  for (const c of ['add', 'sign', 'cycle', 'reveal', 'ecdh', 'members']) assert.deepEqual(call({ call: c, session, key: laptop.key }), { error: 'unknown_call' });
  assert.deepEqual(call({ call: 'block', session, key: box.state.key }), { error: 'cannot_block_box' });
  assert.deepEqual(call({ call: 'unblock', session, key: laptop.key }), { ok: true });
  assert.ok(valid(await D.signEvent(laptop, lh, note(held.npub), send, NOW)));

  // Five wrong tries lock the username; the right password does not help until the lock ends.
  for (let k = 0; k < 5; k++) assert.deepEqual(call({ call: "pw_login", username: "aaron", verifier: bad }), { error: "wrong" });
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: good }), { error: 'locked', wait: 15 * 60 });
  tick(15 * 60 + 1);
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: bad }), { error: 'wrong' });       // sixth: the lock doubles
  assert.equal(call({ call: 'pw_login', username: 'aaron', verifier: good }).wait, 30 * 60);
  tick(30 * 60 + 1);
  assert.match(call({ call: 'pw_login', username: 'aaron', verifier: good }).session, /^[0-9a-f]{64}$/);
  assert.equal(box.only()!.login!.fails, undefined);

  // Logging out everywhere, and sessions ending by themselves.
  const s2 = call({ call: 'pw_login', username: 'aaron', verifier: good }).session;
  call({ call: 'logout_all', session: s2 });
  assert.deepEqual(call({ call: 'me', session }), { error: 'login' });
  const s3 = call({ call: 'pw_login', username: 'aaron', verifier: good }).session;
  tick(12 * 3600 + 1);
  assert.deepEqual(call({ call: 'me', session: s3 }), { error: 'login' });
  // The page changes the password itself: the new one works, the old one does not.
  const s4 = call({ call: 'pw_login', username: 'aaron', verifier: good }).session;
  const salt2 = bytesToHex(randomBytes(16)), v2 = await D.passwordVerifier('a new one', salt2);
  assert.deepEqual(call({ call: 'pw_set', session: s4, username: 'aaron', salt: salt2, check: D.passwordCheck(v2) }), { ok: true });
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: good }), { error: 'wrong' });
  assert.match(call({ call: 'pw_login', username: 'aaron', verifier: v2 }).session, /^[0-9a-f]{64}$/);
  assert.deepEqual(call({ call: 'pw_set', session: 'f'.repeat(64), username: 'aaron', salt: salt2, check: D.passwordCheck(v2) }), { error: 'login' });
  assert.ok(call({ call: 'me', session: s4 }).log.some((l: any) => /password was changed/.test(l.text)));
  // A password is always required: neither a device nor the page can remove it, and it still works.
  await assert.rejects(D.passwordClear(phone, held, send, now()), /password_required/);
  assert.deepEqual(call({ call: 'pw_clear', session: s4 }), { error: 'password_required' });
  assert.match(call({ call: 'pw_login', username: 'aaron', verifier: v2 }).session, /^[0-9a-f]{64}$/);
});

test('the account page: logging in by a device, per account', async () => {
  const { box, send, call } = world();
  const alice = device('Alice'), bob = device('Bob');
  const a = await D.createWithBox(alice, D.readQr(box.qr('http://box')!), send, NOW);
  const b = await D.createWithBox(bob, D.readQr(box.newSetupCode('http://box', NOW)), send, NOW);
  const browser = bytesToHex(randomBytes(16));
  const { code, text } = call({ call: 'login_start', browser });
  assert.equal(JSON.parse(text).login.addr, 'https://account.example');
  assert.deepEqual(call({ call: 'login_wait', code, browser }), { ok: true, waiting: true });
  assert.deepEqual(call({ call: 'login_wait', code, browser: 'a'.repeat(32) }), { error: 'gone' });        // another browser
  await assert.rejects(D.approveLogin({ ...bob, fp: undefined }, b, text, send, NOW), /needs_fingerprint/);
  await D.approveLogin(bob, b, text, send, NOW);
  await assert.rejects(D.approveLogin(alice, a, text, send, NOW), /bad_code/);                              // one use
  const { session } = call({ call: 'login_wait', code, browser });
  assert.equal(call({ call: 'me', session }).npub, b.npub);                                                // Bob's account, not Alice's
  assert.deepEqual(call({ call: 'login_wait', code, browser }), { error: 'gone' });
});

test('grants: the page sees what is signed in, and a revoke sticks on every device', async () => {
  const { box, send, call } = world();
  const phone = device('Phone'), laptop = device('Laptop');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;

  const jumble = D.newGrant('site', 'https://jumble.social', NOW), amethyst = D.newGrant('app', 'Amethyst', NOW);
  assert.deepEqual(await D.reportGrants(laptop, lh, [jumble], send, NOW), []);
  assert.deepEqual(await D.reportGrants(phone, held, [amethyst], send, NOW), []);
  assert.deepEqual(call({ call: 'me', session }).grants.map((g: any) => [g.name, g.kind, g.deviceName]).sort(), [['Amethyst', 'app', 'Phone'], ['https://jumble.social', 'site', 'Laptop']]);
  // Signing for the site names its grant, and works.
  assert.ok(valid(await D.signEvent(laptop, lh, note(held.npub), send, NOW, jumble.id)));
  await D.nip44Encrypt(laptop, lh, held.npub, 'for the site', send, NOW, jumble.id);

  // Revoked from the page: refused from then on, for signing and for message keys, on any device.
  assert.deepEqual(call({ call: 'revoke', session, grant: jumble.id }), { ok: true });
  await assert.rejects(D.signEvent(laptop, lh, note(held.npub), send, NOW, jumble.id), /revoked/);
  await assert.rejects(D.nip44Encrypt(laptop, lh, held.npub, 'x', send, NOW, jumble.id), /revoked/);
  await assert.rejects(D.signEvent(phone, held, note(held.npub), send, NOW, jumble.id), /revoked/);
  assert.ok(valid(await D.signEvent(laptop, lh, note(held.npub), send, NOW)));                              // the person's own use still works
  assert.deepEqual(call({ call: 'me', session }).grants.map((g: any) => g.name), ['Amethyst']);
  // The device learns of it the next time it reports, and a device can revoke too.
  assert.deepEqual(await D.reportGrants(laptop, lh, [jumble], send, NOW), [jumble.id]);
  await D.revoke(laptop, lh, amethyst.id, send, NOW);
  await assert.rejects(D.signEvent(phone, held, note(held.npub), send, NOW, amethyst.id), /revoked/);
  assert.ok(box.only()!.revoked!.length === 2);
});

test('notes: the page starts something and a device finishes it', async () => {
  const { box, send, call, tick } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  const other = device('Other');
  const oh = await D.createWithBox(other, D.readQr(box.newSetupCode('http://box', NOW)), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;

  const { note: id } = call({ call: 'note_put', session, kind: 'bunker', text: '' });
  assert.deepEqual(call({ call: 'note_get', session, note: id }), { ok: true, state: 'waiting', result: undefined });
  assert.deepEqual(await D.notes(other, oh, send, NOW), []);                                               // another account sees nothing
  const waiting = await D.notes(phone, held, send, NOW);
  assert.deepEqual(waiting.map((n) => [n.id, n.kind]), [[id, 'bunker']]);
  await assert.rejects(D.noteDone(other, oh, id, 'bunker://x', send, NOW), /gone/);
  await D.noteDone(phone, held, id, 'bunker://abc?relay=wss%3A%2F%2Fr', send, NOW);
  assert.equal(call({ call: 'note_get', session, note: id }).result, 'bunker://abc?relay=wss%3A%2F%2Fr');
  assert.deepEqual(await D.notes(phone, held, send, NOW), []);                                             // answered: no longer waiting
  await assert.rejects(D.noteDone(phone, held, id, 'again', send, NOW), /gone/);
  // A pasted nostrconnect code travels the same way, and notes do not live long.
  const { note: id2 } = call({ call: 'note_put', session, kind: 'nostrconnect', text: 'nostrconnect://abc?relay=wss://r' });
  assert.equal((await D.notes(phone, held, send, NOW))[0].text, 'nostrconnect://abc?relay=wss://r');
  tick(601);
  assert.deepEqual(call({ call: 'note_get', session, note: id2 }), { error: 'login' }.error ? call({ call: 'note_get', session, note: id2 }) : {});
  assert.equal(call({ call: 'note_get', session, note: id2 }).state, 'gone');
  assert.deepEqual(call({ call: 'note_put', session, kind: 'evil', text: '' }), { error: 'bad_request' });
});

test('a signed-in page has the person\'s authority: devices do what it asks, and only hard-to-undo things ask first', async () => {
  const { box, send, call } = world();
  const phone = device('Phone'), old = device('Old tablet');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.addMember(phone, held, { key: old.key, name: 'Old tablet', kind: 'device', chip: old.chip }, send, NOW);
  await D.join(old, held.boxKey, held.npub, send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const login = async () => call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const session = await login();
  const asked: string[] = [];
  const can = (yes: boolean) => ({ addr: 'https://account.example', tap: async (t: string) => { asked.push(t); return yes; }, bunker: async () => 'bunker://abc?relay=wss%3A%2F%2Fr' });
  const noFp = { ...phone, fp: undefined };          // the phone is at home: nobody is there to give a fingerprint

  // Adding a device from the page: the phone does it with no prompt and no fingerprint.
  const laptop = device('Work laptop');
  const invite = JSON.stringify({ keykin: 2, invite: { key: laptop.key, name: 'Work laptop', chip: laptop.chip } });
  const { note: n1 } = call({ call: 'note_put', session, kind: 'invite', text: invite });
  assert.deepEqual(await D.answerNotes(noFp, held, send, can(true), NOW), ['added Work laptop']);
  assert.deepEqual(asked, []);
  const got1 = call({ call: 'note_get', session, note: n1 });
  const join = JSON.parse(got1.result).join;
  assert.deepEqual(join, { addr: 'https://account.example', boxKey: held.boxKey, npub: held.npub });
  // Added through the page: the piece waits for the code the page was given (SPEC 11.6). This invite came with
  // no challenge (pasted on Devices), so the code alone is enough: the six digits, typed.
  assert.match(got1.approval.short, /^\d{6}$/);
  assert.equal(call({ call: 'note_get', session, note: n1 }).approval, undefined, 'the codes are given once');
  await assert.rejects(D.join(laptop, join.boxKey, join.npub, send, NOW), /not_approved|wrong_code/);
  const lh = await D.join(laptop, join.boxKey, join.npub, send, NOW, { code: got1.approval.short });
  assert.ok(valid(await D.signEvent(laptop, lh, note(held.npub), send, NOW)));
  // Without a note from a signed-in page, the same request with no fingerprint is still refused.
  const stray = device('Stray');
  await assert.rejects(D.addMember(noFp, held, { key: stray.key, name: 'Stray', kind: 'device' }, send, NOW), /needs_fingerprint/);
  await assert.rejects(D.addMember(noFp, held, { key: stray.key, name: 'Stray', kind: 'device' }, send, NOW, 'f'.repeat(32)), /gone/);

  // A bunker link: no prompt either.
  const { note: n3 } = call({ call: 'note_put', session, kind: 'bunker', text: '' });
  assert.ok((await D.answerNotes(noFp, held, send, can(true), NOW)).includes('gave a bunker link'));
  assert.equal(call({ call: 'note_get', session, note: n3 }).result, 'bunker://abc?relay=wss%3A%2F%2Fr');
  assert.deepEqual(asked, []);

  // Removing blocked devices for good is hard to undo: the device asks. No ends that browser's session.
  call({ call: 'block', session, key: old.key });
  call({ call: 'note_put', session, kind: 'cycle', text: '' });
  assert.deepEqual(await D.answerNotes(noFp, held, send, can(false), NOW), ['said No to removing blocked devices']);
  assert.equal(asked.length, 1);
  assert.deepEqual(call({ call: 'me', session }), { error: 'login' });
  assert.equal(box.only()!.epoch, 0);
  // Yes does it.
  const s2 = await login();
  const { note: n5 } = call({ call: 'note_put', session: s2, kind: 'cycle', text: '' });
  assert.deepEqual(await D.answerNotes(noFp, held, send, can(true), NOW), ['removed blocked devices']);
  assert.equal(call({ call: 'note_get', session: s2, note: n5 }).state, 'done');
  assert.equal(box.only()!.epoch, 1);
  assert.deepEqual(box.only()!.members.map((m) => m.name), ['Phone', 'Box', 'Work laptop']);
  const me = call({ call: 'me', session: s2 });
  assert.equal(me.how, 'password');
  assert.ok(me.log.some((l: any) => /said No/.test(l.text)) && me.log.some((l: any) => /Old tablet was blocked/.test(l.text)));
  // And a note for one invite cannot be used to add someone else.
  const { note: n2 } = call({ call: 'note_put', session: s2, kind: 'invite', text: invite.replace(laptop.key, device('Other').key) });
  await assert.rejects(D.addMember(noFp, held, { key: stray.key, name: 'Stray', kind: 'device' }, send, NOW, n2), /bad_member/);
});

// The red team's case (2026-11-19): with `add=` a stranger can put THEIR invite in a link, and a person signed in
// to their account page may press Add. The box keeps the stranger's piece until someone shows the approval code
// the page was given, and the PKCE verifier the challenge was made from. The page hands the code only to a
// loopback address on the same computer (tested in the browser, test/login.test.ts).
test('a device added through the page gets its piece only with the approval code and its verifier', async () => {
  const { box, send, call, tick } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const noFp = { ...phone, fp: undefined };
  const can = { addr: 'https://account.example', tap: async () => false };
  const pkce = () => { const verifier = Buffer.from(randomBytes(32)).toString('base64url'); return { verifier, challenge: Buffer.from(hexToBytes(bytesToHex(schnorrSha(verifier)))).toString('base64url') }; };
  const inviteOf = (m: D.Me) => JSON.stringify({ keykin: 2, invite: { key: m.key, name: m.name } });
  const ask = async (m: D.Me, more: object) => box.handle(JSON.parse(JSON.stringify(await seal({ op: 'welcome', account: held.npub, ...more }, m.sk, NOW))), NOW);

  // A stranger's invite and challenge, in a link; the person presses Add; a phone adds it.
  const stranger = device('Marble on Mac'), sp = pkce();
  const { note: n1 } = call({ call: 'note_put', session, kind: 'invite', text: inviteOf(stranger), challenge: sp.challenge });
  assert.deepEqual(await D.answerNotes(noFp, held, send, can, NOW), ['added Marble on Mac']);
  // Before the page has its codes, and without them after: no piece, whatever the stranger knows.
  assert.deepEqual(await ask(stranger, { verifier: sp.verifier }), { error: 'not_approved' });
  const a1 = call({ call: 'note_get', session, note: n1 }).approval;
  assert.ok(a1.code.length >= 22 && /^\d{6}$/.test(a1.short));
  assert.deepEqual(await ask(stranger, { verifier: sp.verifier }), { error: 'wrong_code' });
  assert.deepEqual(await ask(stranger, { verifier: sp.verifier, code: '123456' === a1.short ? '654321' : '123456' }), { error: 'wrong_code' });
  // Waiting for its code, it can do nothing else: not read the account's notes, not answer them.
  assert.deepEqual(box.handle(JSON.parse(JSON.stringify(await seal({ op: 'notes', account: held.npub }, stranger.sk, NOW))), NOW), { error: 'not_approved' });
  assert.deepEqual(box.handle(JSON.parse(JSON.stringify(await seal({ op: 'members', account: held.npub }, stranger.sk, NOW))), NOW), { error: 'not_approved' });
  // The right code with the wrong verifier is refused too: the code alone is not enough when the invite had a challenge.
  assert.deepEqual(await ask(stranger, { code: a1.code, verifier: pkce().verifier }), { error: 'wrong_code' });
  assert.deepEqual(await ask(stranger, { code: a1.code }), { error: 'wrong_code' });
  assert.deepEqual(await ask(stranger, { code: 'x'.repeat(24), verifier: sp.verifier }), { error: 'wrong_code' });
  // That was the fifth wrong try: the stranger is gone from the list, and even the right code and verifier do nothing now.
  assert.ok(!box.only()!.members.some((m) => m.key === stranger.key));
  assert.deepEqual(await ask(stranger, { code: a1.code, verifier: sp.verifier }), { error: 'unknown_member' });

  // The real app: its own invite and verifier, and the code that came back through the browser.
  const mac = device('Marble on Mac'), mp = pkce();
  const { note: n2 } = call({ call: 'note_put', session, kind: 'invite', text: inviteOf(mac), challenge: mp.challenge });
  await D.answerNotes(noFp, held, send, can, NOW);
  const a2 = call({ call: 'note_get', session, note: n2 }).approval;
  const mh = await D.join(mac, held.boxKey, held.npub, send, NOW, { code: a2.code, verifier: mp.verifier });
  assert.ok(valid(await D.signEvent(mac, mh, note(held.npub), send, NOW)));
  // One use: the code is spent, and another device added the same way cannot use it.
  const other = device('Other'), op = pkce();
  const { note: n3 } = call({ call: 'note_put', session, kind: 'invite', text: inviteOf(other), challenge: op.challenge });
  await D.answerNotes(noFp, held, send, can, NOW);
  const a3 = call({ call: 'note_get', session, note: n3 }).approval;
  assert.deepEqual(await ask(other, { code: a2.code, verifier: op.verifier }), { error: 'wrong_code' });
  // The six digits work with the verifier too, and without naming the account (typed into the app, which knows only the box).
  const typed = box.handle(JSON.parse(JSON.stringify(await seal({ op: 'welcome', code: a3.short, verifier: op.verifier }, other.sk, NOW))), NOW);
  assert.equal(typed.npub, held.npub); assert.equal(typed.boxKey, held.boxKey);

  // Ten minutes after the codes, an unredeemed device goes.
  const late = device('Late'), lp = pkce();
  const { note: n4 } = call({ call: 'note_put', session, kind: 'invite', text: inviteOf(late), challenge: lp.challenge });
  await D.answerNotes(noFp, held, send, can, NOW);
  const a4 = call({ call: 'note_get', session, note: n4 }).approval;
  assert.ok(box.only()!.members.some((m) => m.key === late.key));
  assert.deepEqual(box.handle(JSON.parse(JSON.stringify(await seal({ op: 'welcome', account: held.npub, code: a4.code, verifier: lp.verifier }, late.sk, NOW + 601))), NOW + 601), { error: 'unknown_member' });
  assert.ok(!box.only()!.members.some((m) => m.key === late.key));

  // A bad challenge is refused at the page; a challenge on anything but an invite too.
  assert.deepEqual(call({ call: 'note_put', session, kind: 'invite', text: inviteOf(device('X')), challenge: 'short' }), { error: 'bad_request' });
  assert.deepEqual(call({ call: 'note_put', session, kind: 'bunker', text: '', challenge: mp.challenge }), { error: 'bad_request' });

  // Added by a phone scan (the fingerprint, no page note): unchanged, no code.
  const tablet = device('Tablet');
  await D.addMember(phone, held, { key: tablet.key, name: 'Tablet', kind: 'device', chip: tablet.chip }, send, NOW);
  const th = await D.join(tablet, held.boxKey, held.npub, send, NOW);
  assert.ok(valid(await D.signEvent(tablet, th, note(held.npub), send, NOW)));
});

test('hard-to-undo signatures need a Yes on the device, the ones never done by accident the fingerprint; ordinary ones neither', async () => {
  const { box, send } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  const ev = (kind: number, tags: string[][], content = '') => ({ pubkey: held.npub, created_at: NOW, kind, tags, content });
  const many = ['1', '2', '3', '4', '5'].map((x) => ['e', x.repeat(64)]);
  const hard = [ev(5, many), ev(1, [], 'later')].map((e, i) => (i === 1 ? { ...e, created_at: NOW + 3600 } : e));
  const never = [ev(62, [['relay', 'ALL_RELAYS']]), ev(3, []), ev(0, [], '{}'), ev(0, [], '{"name":"  "}'), ev(5, [['a', `3:${held.npub}:`]])];
  const fine = [ev(1, []), ev(5, many.slice(0, 4)), ev(3, [['p', 'a'.repeat(64)]]), ev(0, [], '{"name":"Aaron"}'), ev(7, [['e', 'a'.repeat(64)]], '+')];
  for (const e of hard) await assert.rejects(D.signEvent(phone, held, e, send, NOW), /needs_tap/);
  for (const e of hard) assert.ok(valid(await D.signEvent(phone, held, e, send, NOW, undefined, true)));
  for (const e of never) {
    await assert.rejects(D.signEvent(phone, held, e, send, NOW), /needs_fingerprint/);
    await assert.rejects(D.signEvent(phone, held, e, send, NOW, undefined, true), /needs_fingerprint/, 'tapped alone');
    assert.ok(valid(await D.signEvent(phone, held, e, send, NOW, undefined, true, undefined, phone.fp)));
  }
  // A second device with no chip key (a phone with no fingerprint set up) is told so, in the box's words.
  const bare = { ...newMemberKey(), name: 'Old phone' };
  await D.addMember(phone, held, { key: bare.key, name: bare.name, kind: 'device' }, send, NOW);
  const bh = await D.join(bare, held.boxKey, held.npub, send, NOW);
  await assert.rejects(D.signEvent(bare, bh, never[0], send, NOW, undefined, true), (e: any) => e.code === 'no_chip_key' && e.why === 'Ask relays to erase everything you have ever published');
  assert.ok(valid(await D.signEvent(bare, bh, hard[0], send, NOW, undefined, true)), 'level 1 is unchanged for it');
  for (const e of fine) assert.ok(valid(await D.signEvent(phone, held, e, send, NOW)));
  // The box notes when the device last signed.
  assert.ok(box.only()!.members[0].last! > 0);
});

test('bringing in a key the person already has: same npub, in pieces from then on', async () => {
  const { box, send, call } = world();
  const nsec = bytesToHex(randomBytes(32));
  const npub = bytesToHex(schnorr.getPublicKey(hexToBytes(nsec)));
  const phone = device('Phone');
  const qr = D.readQr(box.qr('http://box')!);
  // A wrong code, and a piece that is not on the line it claims, are refused.
  await assert.rejects(D.importWithBox(phone, { ...qr, code: 'nope' }, nsec, send, NOW), /bad_code/);
  await assert.rejects(D.importWithBox(phone, qr, 'zz', send, NOW), /bad_key/);
  const other = bytesToHex(randomBytes(32));
  const forged = await seal({ op: 'import', request: qr.code, commitment: (await import('../src/frost.ts')).deal(BigInt('0x' + nsec)).commitment.map((p: any) => p.toHex(true)),
    share: (await import('../src/seal.ts')).sealTo(phone.sk, qr.key, 'import', other), name: 'x' }, phone.sk, NOW);
  assert.deepEqual(box.handle(forged, NOW), { error: 'bad_piece' });

  const held = await D.importWithBox(phone, qr, nsec, send, NOW);
  assert.equal(held.npub, npub);                                   // the same identity as before
  assert.doesNotMatch(JSON.stringify(box.state), new RegExp(nsec));
  const ev = await D.signEvent(phone, held, note(npub), send, NOW);
  assert.ok(valid(ev)); assert.equal(ev.pubkey, npub);
  // Everything else works as for a key made together: another device, messages, and the key formed again by fingerprint.
  const laptop = device('Laptop');
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, send, NOW);
  assert.ok(valid(await D.signEvent(laptop, lh, note(npub), send, NOW)));
  const formed = await D.formNsec(laptop, lh, send, NOW);
  assert.equal(bytesToHex(schnorr.getPublicKey(hexToBytes(formed))), npub);
  // The same key cannot be brought to this box twice, and the first-run code is spent.
  await assert.rejects(D.importWithBox(device('Again'), D.readQr(box.newSetupCode('http://box', NOW)), nsec, send, NOW), /already_here/);
  assert.equal(box.accounts().length, 1);
  assert.ok(box.only()!.log!.some((l) => /existing key/.test(l.text)));
  assert.ok(call);
});

test('moving an account to another box: same npub, the key never whole, the old box left behind', async () => {
  const oldW = world(), newW = world();
  const phone = device('Phone'), laptop = device('Laptop');
  const held = await D.createWithBox(phone, D.readQr(oldW.box.qr('http://old')!), oldW.send, NOW);
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, oldW.send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, oldW.send, NOW);
  const npub = held.npub, oldKey = oldW.box.state.key, before = await D.formNsec(phone, held, oldW.send, NOW);
  // The new box already holds someone else's account, so this needs its admin's yes.
  await D.createWithBox(device('Someone else'), D.readQr(newW.box.qr('http://new')!), newW.send, NOW);
  const id = await D.askBox(phone, 'transfer', 'moving from my old box', newW.send, NOW, npub);
  const target = { key: newW.box.state.key, code: id };
  await assert.rejects(D.transferToBox({ ...phone, fp: undefined }, held, oldW.send, target, newW.send, NOW), /needs_fingerprint/);
  assert.equal(held.boxKey, oldKey);
  const fresh = D.readQr(oldW.box.qr('x') ?? JSON.stringify({ keykin: 2, addr: 'x', key: oldKey, code: 'x' }));
  assert.ok(fresh);
  newW.box.decide(id, true, NOW);

  await D.transferToBox(phone, held, oldW.send, target, newW.send, NOW);
  assert.equal(held.boxKey, newW.box.state.key); assert.equal(held.npub, npub);
  const a = newW.box.state.accounts[npub];
  assert.deepEqual(a.members.map((m) => [m.name, m.kind]).sort(), [['Box', 'box'], ['Laptop', 'device'], ['Phone', 'device']]);
  assert.ok(!a.members.some((m) => m.key === oldKey));
  // The phone signs with the new box at once. The same key as before.
  const ev = await D.signEvent(phone, held, note(npub), newW.send, NOW);
  assert.ok(valid(ev)); assert.equal(ev.pubkey, npub);
  assert.equal(await D.formNsec(phone, held, newW.send, NOW), before);
  // The laptop is told the new box, and catches up on its first request there.
  lh.boxKey = newW.box.state.key;
  assert.ok(valid(await D.signEvent(laptop, lh, note(npub), newW.send, NOW)));
  // The old box's piece no longer fits with anyone's: it cannot help the phone sign any more.
  const old = oldW.box.state.accounts[npub];
  const msg = eventId(note(npub));
  const { ask, answer, finish } = await import('../src/round.ts');
  const { commitmentFrom } = await import('../src/curve.ts');
  const mine = ask(held.piece, msg);
  assert.throws(() => finish(held.piece, msg, mine, answer({ C: commitmentFrom(old.commitment), i: old.i, share: BigInt('0x' + old.share) }, msg, mine.commit)), /bad_partial|bad_signature/);
  // The other account on the new box is untouched, and a request cannot be used twice.
  assert.equal(newW.box.accounts().length, 2);
  await assert.rejects(D.transferToBox(phone, held, newW.send, target, newW.send, NOW), /bad_code|already_listed|bad_member/);
});

test('removing a box: another box in the account is blocked and cycled away like a device; this box cannot be', async () => {
  const { box, send, call } = world();
  const { adminPage } = await import('../box/page.ts');
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  // A second box joins the account as a backup and collects its piece, as a box does: it signs its own request.
  const backup = new Box();
  await D.addMember(phone, held, { key: backup.state.key, name: 'Backup box', kind: 'box' }, send, NOW);
  const fetched = box.handle(await seal({ op: 'welcome', account: held.npub }, backup.state.sk, NOW), NOW);
  assert.equal(fetched.ok, true);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;

  // Only the box answering has no Block button, on the admin page and on the account page's list.
  const html = adminPage({ accounts: box.accounts(), requests: [], boxKey: box.state.key, csrf: 'x', logout: false, where: { host: 'box', behindLogin: true }, door: { seen: 0, side: false }, now: NOW });
  assert.match(html, /aria-label="Block Backup box"/); assert.doesNotMatch(html, /aria-label="Block Box"/);
  assert.match(html, /another box/);
  assert.equal(call({ call: 'me', session }).boxKey, box.state.key);
  // This box still cannot be blocked, by a device, the page or the admin.
  await assert.rejects(D.block(phone, box.state.key, send, NOW, held.npub), /cannot_block_box/);
  assert.deepEqual(call({ call: 'block', session, key: box.state.key }), { error: 'cannot_block_box' });
  assert.throws(() => box.ownerBlock(box.state.key), /cannot_block_box/);
  // The other box can: one press, then a cycle removes it for good and its piece stops fitting.
  await D.block(phone, backup.state.key, send, NOW, held.npub);
  assert.equal(box.handle(await seal({ op: 'members', account: held.npub }, backup.state.sk, NOW), NOW).error, 'blocked');
  await D.cycle(phone, held, send, NOW);
  assert.deepEqual(box.only()!.members.map((m) => [m.name, m.kind]), [['Phone', 'device'], ['Box', 'box']]);
  assert.equal(box.handle(await seal({ op: 'members', account: held.npub }, backup.state.sk, NOW), NOW).error, 'unknown_member');
  assert.ok(valid(await D.signEvent(phone, held, note(held.npub), send, NOW)));
  // Unblocking a box is the same as a device's: the admin, or the page, may.
  const spare = new Box();
  await D.addMember(phone, held, { key: spare.state.key, name: 'Spare box', kind: 'box' }, send, NOW);
  assert.deepEqual(call({ call: 'block', session, key: spare.state.key }), { ok: true });
  assert.deepEqual(call({ call: 'unblock', session, key: spare.state.key }), { ok: true });
  assert.equal(box.only()!.members.find((m) => m.name === 'Spare box')!.blocked, false);
});

test('per-site limits: a grant limited to posting signs posts only and gets no message keys', async () => {
  const { box, send, call } = world();
  const phone = device('Phone'), laptop = device('Laptop');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const site = D.newGrant('site', 'https://jumble.social', NOW), app = D.newGrant('app', 'Amethyst', NOW);
  await D.reportGrants(laptop, lh, [site], send, NOW);
  await D.reportGrants(phone, held, [app], send, NOW);
  const ev = (kind: number, tags: string[][] = [], content = 'x') => ({ pubkey: held.npub, created_at: NOW, kind, tags, content });
  const limits = () => Object.fromEntries(call({ call: 'me', session }).grants.map((g: any) => [g.name, g.limit]));
  assert.deepEqual(limits(), { 'https://jumble.social': null, Amethyst: null });

  // Set from the account page.
  assert.deepEqual(call({ call: 'limit', session, grant: site.id, to: 'posts' }), { ok: true });
  assert.deepEqual(limits(), { 'https://jumble.social': 'posts', Amethyst: null });
  for (const k of [1, 6, 7, 16, 1111, 9734, 20, 21, 22, 22242]) assert.ok(valid(await D.signEvent(laptop, lh, ev(k, [['e', 'a'.repeat(64)]]), send, NOW, site.id)), `kind ${k}`);
  for (const k of [0, 3, 4, 5, 9735, 10002, 30023]) await assert.rejects(D.signEvent(laptop, lh, ev(k, [['p', 'a'.repeat(64)]], '{"name":"x"}'), send, NOW, site.id), /not_allowed/, `kind ${k}`);
  await assert.rejects(D.nip44Encrypt(laptop, lh, held.npub, 'can it read?', send, NOW, site.id), /not_allowed/);
  // Only that grant: another one, and the person's own use, are untouched, on any device.
  // (The person's own profile first: an app's write of a list the box has no version of is asked about.)
  await D.signEvent(phone, held, { ...ev(0, [], '{"name":"Aaron"}'), created_at: NOW - 1 }, send, NOW);
  assert.ok(valid(await D.signEvent(phone, held, ev(0, [], '{"name":"Aaron"}'), send, NOW, app.id)));
  assert.ok(valid(await D.signEvent(laptop, lh, ev(3, [['p', 'a'.repeat(64)]]), send, NOW)));
  await D.nip44Encrypt(laptop, lh, held.npub, 'mine', send, NOW);
  await assert.rejects(D.signEvent(phone, held, ev(3, [['p', 'a'.repeat(64)]]), send, NOW, site.id), /not_allowed/);

  // Lifted from a device, and set again from a device.
  await D.limit(phone, held, site.id, null, send, NOW);
  assert.ok(valid(await D.signEvent(laptop, lh, ev(3, [['p', 'a'.repeat(64)]]), send, NOW, site.id)));
  await D.limit(laptop, lh, app.id, 'posts', send, NOW);
  await assert.rejects(D.nip44Decrypt(phone, held, held.npub, 'x', send, NOW, app.id), /not_allowed/);
  assert.deepEqual(limits(), { 'https://jumble.social': null, Amethyst: 'posts' });
  assert.ok(call({ call: 'me', session }).log.some((l: any) => /jumble.social was limited to posting/.test(l.text)));
  // Bad requests, and a grant the page does not know.
  await assert.rejects(D.limit(phone, held, app.id, 'everything' as any, send, NOW), /bad_request/);
  assert.deepEqual(call({ call: 'limit', session, grant: 'f'.repeat(32), to: 'posts' }), { error: 'gone' });
  // Revoking takes the limit with it.
  call({ call: 'revoke', session, grant: app.id });
  assert.equal(box.only()!.limits![app.id], undefined);
});

// A passkey made in the test, signing the way an authenticator does (ES256), so a real pk_login runs.
async function testPasskey(rpId: string) {
  const { generateKeyPairSync, createHash, sign } = await import('node:crypto');
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' }) as any;
  const b = (s: string) => Buffer.from(s, 'base64url');
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), b(jwk.x), Buffer.from([0x22, 0x58, 0x20]), b(jwk.y)]);
  const id = bytesToHex(randomBytes(16));
  const credId = Buffer.from(id, 'hex').toString('base64url');
  let counter = 0;
  return {
    record: { id: credId, key: cose.toString('base64url'), counter: 0, rpId, origin: `https://${rpId}`, added: NOW },
    answer(challenge: string) {
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://${rpId}`, crossOrigin: false }));
      const c = Buffer.alloc(4); c.writeUInt32BE(++counter);
      const auth = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x05]), c]);
      const sig = sign('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), privateKey);
      return { id: credId, rawId: credId, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: sig.toString('base64url') } };
    },
  };
}

test('page sessions: a passkey lasts 90 days from its last use, a password or a scan 12 hours; kept hashed in the state; signed-in browsers', async () => {
  const { box, page, send, call, tick, now } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const pk = await testPasskey('account.example');
  box.only()!.passkeys = [pk.record];
  const origin = 'https://account.example';
  const withPasskey = async (agent: string) => {
    const s = await page.request({ call: 'pk_login_start', origin }, now());
    return (await page.request({ call: 'pk_login', origin, response: pk.answer(s.options.challenge), agent }, now())).session as string;
  };
  const withPassword = async (agent?: string) => call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt), agent }).session as string;

  // A passkey: 90 days, and each call starts them again.
  const p = await withPasskey('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36' + 'x'.repeat(300));
  assert.match(p, /^[0-9a-f]{64}$/);
  assert.equal(call({ call: 'me', session: p }).how, 'passkey');
  tick(89 * 86400); assert.equal(call({ call: 'me', session: p }).ok, true);
  tick(89 * 86400); assert.equal(call({ call: 'me', session: p }).ok, true);
  tick(90 * 86400 - 10); assert.equal(call({ call: 'me', session: p }).ok, true);
  tick(90 * 86400 + 1); assert.deepEqual(call({ call: 'me', session: p }), { error: 'login' });

  // A password: 12 hours from sign-in, however much it is used.
  const w = await withPassword();
  for (let k = 0; k < 11; k++) { tick(3600); assert.equal(call({ call: 'me', session: w }).ok, true); }
  tick(3601); assert.deepEqual(call({ call: 'me', session: w }), { error: 'login' });
  // A scan: the same 12 hours.
  const browser = bytesToHex(randomBytes(16));
  const { code, text } = call({ call: 'login_start', browser });
  await D.approveLogin(phone, held, text, send, now());
  const scan = call({ call: 'login_wait', code, browser, agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15' }).session;
  tick(6 * 3600); assert.equal(call({ call: 'me', session: scan }).how, 'scan');
  tick(6 * 3600 + 1); assert.deepEqual(call({ call: 'me', session: scan }), { error: 'login' });

  // The state keeps SHA-256(token), never the token, and lives through a restart of the box.
  const p2 = await withPasskey('Firefox on Linux'), w2 = await withPassword('Chrome on Android');
  const { createHash } = await import('node:crypto');
  const saved = JSON.stringify(box.state);
  for (const t of [p2, w2]) { assert.ok(!saved.includes(t)); assert.ok(saved.includes(createHash('sha256').update(t).digest('hex'))); }
  const again = new Box(JSON.parse(saved)), page2 = new PageApi(again, () => 'https://account.example');
  const call2 = (body: object) => page2.call(JSON.parse(JSON.stringify(body)), now());
  assert.equal(call2({ call: 'me', session: p2 }).how, 'passkey');
  assert.equal(call2({ call: 'me', session: w2 }).how, 'password');

  // The signed-in browsers: newest use first, each with how, when, the browser, and which one is asking.
  tick(60);
  call2({ call: 'me', session: w2 });
  const list = call2({ call: 'me', session: p2 }).browsers;
  assert.deepEqual(list.map((x: any) => [x.how, x.agent, x.this]), [['passkey', 'Firefox on Linux', true], ['password', 'Chrome on Android', false]]);
  const mine = list[0], other = list[1];
  assert.match(mine.id, /^[0-9a-f]{16}$/); assert.equal(mine.id, createHash('sha256').update(p2).digest('hex').slice(0, 16));
  assert.equal(mine.until, mine.last + 90 * 86400); assert.equal(other.until, other.made + 12 * 3600);
  assert.ok(other.made < other.last);
  // Agents are cut to 200 characters.
  assert.ok(Object.values(again.state.sessions!).every((s) => s.agent.length <= 200));
  // Sign one out: it is gone, the one asking is not. Another account's browser cannot be named.
  assert.deepEqual(call2({ call: 'logout_browser', session: p2, id: other.id }), { ok: true, this: false });
  assert.deepEqual(call2({ call: 'me', session: w2 }), { error: 'login' });
  assert.deepEqual(call2({ call: 'logout_browser', session: p2, id: other.id }), { error: 'gone' });
  assert.deepEqual(call2({ call: 'logout_browser', session: p2, id: 'nope' }), { error: 'bad_request' });
  assert.ok(call2({ call: 'me', session: p2 }).log.some((l: any) => l.text === 'A browser was signed out from the account page'));
  assert.deepEqual(call2({ call: 'logout_browser', session: p2, id: mine.id }), { ok: true, this: true });
  assert.deepEqual(call2({ call: 'me', session: p2 }), { error: 'login' });
  assert.deepEqual(again.state.sessions, {});
});

test('a grant ends after 90 days unused: the box answers revoked and says so', async () => {
  const { box, send, call, tick, now } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const login = async () => call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const used = D.newGrant('site', 'https://used.example', NOW), idle = D.newGrant('site', 'https://idle.example', NOW), app = D.newGrant('app', 'Amethyst', NOW);
  await D.reportGrants(phone, held, [used, idle, app], send, NOW);
  // Use is any request naming it: signing or a message key.
  tick(60 * 86400);
  assert.ok(valid(await D.signEvent(phone, held, note(held.npub), send, now(), used.id)));
  await D.nip44Encrypt(phone, held, held.npub, 'x', send, now(), app.id);
  const session = await login();
  const last = () => Object.fromEntries(call({ call: 'me', session }).grants.map((g: any) => [g.name, g.last]));
  assert.deepEqual(last(), { 'https://used.example': now(), 'https://idle.example': null, Amethyst: now() });
  // 90 days after its `since`, the one never used ends; the others carry on from their last use.
  tick(30 * 86400 + 1);
  await assert.rejects(D.signEvent(phone, held, note(held.npub), send, now(), idle.id), /revoked/);
  assert.ok(valid(await D.signEvent(phone, held, note(held.npub), send, now(), used.id)));
  const s2 = await login();
  assert.deepEqual(call({ call: 'me', session: s2 }).grants.map((g: any) => g.name).sort(), ['Amethyst', 'https://used.example']);
  assert.ok(call({ call: 'me', session: s2 }).log.some((l: any) => l.text === 'https://idle.example signed out after 90 days unused'));
  // The device learns of it from its next report.
  assert.deepEqual(await D.reportGrants(phone, held, [used, idle, app], send, now()), [idle.id]);
  // The app was last used 30 days ago; 60 more days and a day, and it ends at the next report even with no request.
  tick(60 * 86400 + 1);
  assert.deepEqual(await D.reportGrants(phone, held, [used, app], send, now()), [app.id]);
  await assert.rejects(D.nip44Encrypt(phone, held, held.npub, 'x', send, now(), app.id), /revoked/);
  assert.ok(valid(await D.signEvent(phone, held, note(held.npub), send, now(), used.id)));        // used 61 days ago: still fine
  assert.equal(box.only()!.used![idle.id], undefined);
});

test('a nostrconnect note carries where it came from and which key, and a device reads them back', async () => {
  const { box, send, call } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const code = 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss://r&secret=s&url=https://marble.example';
  const a = call({ call: 'note_put', session, kind: 'nostrconnect', text: code, from: 'https://marble.example', as: 'site' });
  const b = call({ call: 'note_put', session, kind: 'nostrconnect', text: code, from: null, as: 'main' });
  const c = call({ call: 'note_put', session, kind: 'nostrconnect', text: code });                   // an older page sends neither
  const d = call({ call: 'note_put', session, kind: 'bunker', text: '', from: 'https://x.example', as: 'site' });
  for (const bad of [{ from: 'javascript:alert(1)' }, { from: 'https://a.example/path' }, { from: 7 }, { as: 'other' }, { from: 'https://' + 'a'.repeat(200) }])
    assert.deepEqual(call({ call: 'note_put', session, kind: 'nostrconnect', text: code, ...bad }), { error: 'bad_request' }, JSON.stringify(bad));
  const got = await D.notes(phone, held, send, NOW);
  assert.deepEqual(got.map((n) => [n.id, n.kind, n.from, n.as]), [
    [a.note, 'nostrconnect', 'https://marble.example', 'site'], [b.note, 'nostrconnect', null, 'main'], [c.note, 'nostrconnect', null, 'main'], [d.note, 'bunker', undefined, undefined]]);
});

test('grants carry who they are: client key, device label, how, the browser that left the code, and the last kind', async () => {
  const { box, send, call } = world();
  const phone = device('Pixel 9a');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const win = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36';
  const session = call({ call: 'pw_login', username: 'aaron', agent: win, verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const client = 'ab12'.padEnd(64, '0'), other = 'cd34'.padEnd(64, '0');
  call({ call: 'note_put', session, kind: 'nostrconnect', text: `nostrconnect://${client}?relay=wss://r&device=Chrome%20on%20Windows`, from: 'https://marble.syb.lol' });
  const a = { ...D.newGrant('site', 'https://marble.syb.lol', NOW), client, device: '  Chrome on Windows' + 'x'.repeat(80), via: 'login' as const, browser: 'forged' };
  const b = { ...D.newGrant('site', 'https://marble.syb.lol', NOW), client: other, via: 'scan' as const };
  const c = { ...D.newGrant('site', 'https://marble.syb.lol', NOW), client: 'nothex', via: 'evil' as any };
  await D.reportGrants(phone, held, [a, b, c], send, NOW);
  await D.signEvent(phone, held, { ...note(held.npub), kind: 7 }, send, NOW, a.id);
  const rows = Object.fromEntries(call({ call: 'me', session }).grants.map((g: any) => [g.id, g]));
  assert.equal(rows[a.id].client, client);
  assert.equal(rows[a.id].device, 'Chrome on Windows' + 'x'.repeat(43));             // trimmed, 60 at most
  assert.equal(rows[a.id].via, 'login');
  assert.equal(rows[a.id].browser, 'Chrome on Windows');                            // the box's word, not the device's
  assert.equal(rows[a.id].lastKind, 7);
  assert.equal(rows[a.id].deviceName, 'Pixel 9a');
  assert.equal(rows[b.id].browser, undefined); assert.equal(rows[b.id].via, 'scan'); assert.equal(rows[b.id].lastKind, null);
  assert.equal(rows[c.id].client, undefined); assert.equal(rows[c.id].via, undefined);
  // Revoking forgets the kind too.
  call({ call: 'revoke', session, grant: a.id });
  assert.equal(box.only()!.kinds?.[a.id], undefined);
});

test('the Sites and apps detail line', async () => {
  process.env.TZ = 'UTC';
  // @ts-ignore: a plain script for the page
  await import('../login/static/rows.js');
  const { siteDetail, kindWord } = (globalThis as any).KeykinRows;
  const since = Date.UTC(2026, 10, 19, 6, 14) / 1000;
  const g = { kind: 'site', since, via: 'login', device: 'Chrome on Windows', browser: 'Firefox on Linux', deviceName: 'Pixel 9a', last: since + 3600, lastKind: 7, client: 'ab12'.padEnd(64, '0') };
  assert.equal(siteDetail(g, since + 3 * 3600), 'Chrome on Windows · signed in 19 Nov 06:14 through your login page · approved by Pixel 9a · last used 2 h ago, last posted a reaction · key ab12…');
  assert.equal(siteDetail({ kind: 'site', since, deviceName: 'Pixel 9a', last: null }, since), 'signed in 19 Nov 06:14 · approved by Pixel 9a · not used yet');
  assert.equal(siteDetail({ kind: 'site', since, browser: 'Safari on macOS', via: 'scan', deviceName: 'P', last: since, lastKind: 30023 }, since + 30), 'Safari on macOS · signed in 19 Nov 06:14 by a scanned code · approved by P · last used a minute ago, last posted an article');
  assert.equal(siteDetail({ kind: 'app', since, deviceName: 'Pixel 9a', last: null }, since), 'App on Pixel 9a · added 19 Nov 06:14 · not used yet');
  assert.deepEqual([0, 1, 4, 6, 7, 99999].map(kindWord), ['profile', 'note', 'DM', 'repost', 'reaction', 'kind 99999 event']);
  for (const s of [siteDetail(g, since)]) assert.ok(!s.includes('—'));
  // A site's switches: the page's want shows until the device reports the same, and the line says who it waits for.
  const { scopeShown, scopeWaiting } = (globalThis as any).KeykinRows;
  const s = { kind: 'site', since, deviceName: 'Pixel 9a', last: null, lists: false, dms: false, want: { dms: true } };
  assert.equal(siteDetail(s, since), 'signed in 19 Nov 06:14 · approved by Pixel 9a · not used yet · waiting for Pixel 9a');
  assert.deepEqual([scopeShown(s, 'dms'), scopeShown(s, 'lists')], [true, false]);
  assert.equal(scopeWaiting({ ...s, dms: true }), null);
  assert.equal(scopeWaiting({ ...s, want: null }), null);
});

test('a site\'s switches: the page turns DMs and private lists on or off, and the device that let it in picks it up', async () => {
  const { box, send, call, tick, now } = world();
  const phone = device('Pixel 9a'), laptop = device('Laptop');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send, NOW);
  const lh = await D.join(laptop, held.boxKey, held.npub, send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const chat: D.Grant = { ...D.newGrant('site', 'https://chat.nostr.com', NOW), lists: false, dms: false, via: 'bunker' };
  const plain = D.newGrant('site', 'https://jumble.social', NOW), app = D.newGrant('app', 'Amethyst', NOW);
  const other: D.Grant = { ...D.newGrant('site', 'https://other.example', NOW), lists: true, dms: 'yes' as any };
  // A reported grant keeps its switches; anything but a boolean is dropped.
  assert.deepEqual(await D.syncGrants(phone, held, [chat, plain, app, other], send, NOW), { revoked: [], scopes: {} });
  const rows = () => Object.fromEntries(call({ call: 'me', session }).grants.map((g: any) => [g.name, [g.lists, g.dms, g.want]]));
  assert.deepEqual(rows(), { 'https://chat.nostr.com': [false, false, null], 'https://jumble.social': [null, null, null], Amethyst: [null, null, null], 'https://other.example': [true, null, null] });
  assert.equal(box.only()!.grants![phone.key].find((g) => g.id === other.id)!.dms, undefined);

  // The page turns DMs on: kept as a want, said in the activity list, and handed to that device only.
  assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, dms: true }), { ok: true });
  assert.deepEqual(rows()['https://chat.nostr.com'], [false, false, { dms: true }]);
  assert.ok(call({ call: 'me', session }).log.some((l: any) => l.text === 'chat.nostr.com may read and send DMs, from the account page'));
  assert.deepEqual(await D.syncGrants(laptop, lh, [], send, NOW), { revoked: [], scopes: {} });
  assert.deepEqual(await D.syncGrants(phone, held, [chat, plain, app, other], send, NOW), { revoked: [], scopes: { [chat.id]: { dms: true } } });
  // A second change merges with the first, and comes again until the device reports it.
  assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, lists: true }), { ok: true });
  assert.ok(call({ call: 'me', session }).log.some((l: any) => l.text === 'chat.nostr.com may read your private lists, from the account page'));
  assert.deepEqual((await D.syncGrants(phone, held, [chat, plain, app, other], send, NOW)).scopes, { [chat.id]: { dms: true, lists: true } });
  // The device reports DMs on: that part is done, the lists part still waits.
  assert.deepEqual((await D.syncGrants(phone, held, [{ ...chat, dms: true }, plain, app, other], send, NOW)).scopes, { [chat.id]: { lists: true } });
  assert.deepEqual((await D.syncGrants(phone, held, [{ ...chat, dms: true, lists: true }, plain, app, other], send, NOW)).scopes, {});
  assert.deepEqual(rows()['https://chat.nostr.com'], [true, true, null]);
  assert.equal(box.only()!.wants, undefined);
  // Turning one off is said too.
  call({ call: 'scopes', session, grant: chat.id, dms: false });
  assert.ok(call({ call: 'me', session }).log.some((l: any) => l.text === 'chat.nostr.com may no longer read and send DMs, from the account page'));
  assert.deepEqual(rows()['https://chat.nostr.com'], [true, true, { dms: false }]);

  // Refused: a grant not on the list, an app, a site without switches, a switch it does not report, and bad bodies.
  assert.deepEqual(call({ call: 'scopes', session, grant: 'f'.repeat(32), dms: true }), { error: 'gone' });
  assert.deepEqual(call({ call: 'scopes', session, grant: app.id, dms: true }), { error: 'bad_request' });
  assert.deepEqual(call({ call: 'scopes', session, grant: plain.id, lists: true }), { error: 'bad_request' });
  assert.deepEqual(call({ call: 'scopes', session, grant: other.id, dms: true }), { error: 'bad_request' });
  for (const bad of [{}, { dms: 'yes' }, { lists: 1 }, { dms: null }])
    assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, ...bad }), { error: 'bad_request' }, JSON.stringify(bad));
  assert.deepEqual(box.only()!.wants, { [chat.id]: { dms: false } });

  // Revoking takes the want with it, and so does ending after 90 days unused.
  call({ call: 'revoke', session, grant: chat.id });
  assert.equal(box.only()!.wants, undefined);
  assert.deepEqual(call({ call: 'scopes', session, grant: other.id, lists: false }), { ok: true });
  tick(91 * 86400);
  assert.deepEqual(call({ call: 'me', session: call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session }).grants, []);
  assert.deepEqual(box.only()!.wants ?? {}, {});
  assert.deepEqual(await D.reportGrants(phone, held, [other], send, now()), [other.id]);
});

test('a site\'s switches follow the limit gate: a weak page session may turn one off but not on', async () => {
  const box = new Box();
  const page = new PageApi(box, () => 'https://account.example', () => false, { calls: { 'limit:none': 'strong' } });
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), NOW);
  const call = (body: object) => page.call(JSON.parse(JSON.stringify(body)), NOW);
  const phone = device('Pixel 9a');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  const chat: D.Grant = { ...D.newGrant('site', 'https://chat.nostr.com', NOW), lists: true, dms: false };
  await D.reportGrants(phone, held, [chat], send, NOW);
  assert.deepEqual(call({ call: 'limit', session, grant: chat.id, to: null }), { error: 'need_strong' });
  assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, dms: true }), { error: 'need_strong' });
  assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, lists: false, dms: true }), { error: 'need_strong' });
  assert.deepEqual(call({ call: 'scopes', session, grant: chat.id, lists: false }), { ok: true });
  assert.deepEqual(call({ call: 'me', session }).grants[0].want, { lists: false });
});

test('a bunker link names its site: the name typed on the page, else the site\'s first client tag; the box lists it', async () => {
  const { box, send, call, tick } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw', send, NOW);
  const session = call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw', call({ call: 'pw_salt', username: 'aaron' }).salt) }).session;
  tick(Math.floor(Date.now() / 1000) - NOW);           // a bunker signs at the real time
  const T = Math.floor(Date.now() / 1000);
  const b = newBunker(), bunkerKey = getPublicKey(hexToBytes(b.sk));
  let changes = 0; const changed = () => { changes++; };
  const ask = (client: string, method: string, params: string[]) => answerRequest(b, phone, held, send, client, method, params, changed);
  const post = (client: string, tags: string[][]) => ask(client, 'sign_event', [JSON.stringify({ kind: 1, created_at: T, tags, content: 'hi' })]);
  const names = async () => { await syncGrants(b, phone, held, send); return call({ call: 'me', session }).grants.map((g: any) => g.name).sort(); };
  const secretOf = (link: string) => new URL(link.replace('bunker://', 'https://')).searchParams.get('secret')!;
  let asked: any;
  const can = { addr: 'https://account.example', tap: async () => false, bunker: async (o: any) => { asked = o; return bunkerTicket(b, 'wss://r', o); } };

  // The page asks for a link with a name and both switches. The note carries them; the device cleans the name.
  const { note } = call({ call: 'note_put', session, kind: 'bunker', text: ' \u0007Jumble\n', lists: true, dms: true });
  const [n] = await D.notes(phone, held, send, T);
  assert.deepEqual([n.text, n.lists, n.dms], [' \u0007Jumble\n', true, true]);
  assert.deepEqual(await D.answerNotes(phone, held, send, can, T), ['gave a bunker link']);
  assert.deepEqual(asked, { name: 'Jumble', lists: true, dms: true });
  const jumble = bytesToHex(randomBytes(32));
  await ask(jumble, 'connect', [bunkerKey, secretOf(call({ call: 'note_get', session, note }).result)]);
  assert.deepEqual(b.scopes?.[jumble], { lists: true, dms: true });
  assert.deepEqual(await names(), ['Jumble']);
  // The typed name wins over the site's own client tag.
  changes = 0;
  assert.ok(valid(JSON.parse(await post(jumble, [['client', 'Other app']]))));
  assert.equal(b.grants![jumble].name, 'Jumble'); assert.equal(changes, 0);

  // A site in by the plain link, with no name: "A site" until a post carries a client tag. The first tag names it, once.
  const plain = bytesToHex(randomBytes(32));
  await ask(plain, 'connect', [bunkerKey, b.secret]);
  assert.match((await names())[0], /^A site \(/);
  await post(plain, [['t', 'keykin']]);
  assert.equal(changes, 1);                                // only the connect
  await post(plain, [['client', ''], ['client', '  Coracle  ', '31990:abc:def', 'wss://r']]);
  assert.equal(b.grants![plain].name, 'Coracle'); assert.equal(changes, 2);
  assert.deepEqual(await names(), ['Coracle', 'Jumble']); // the box takes the renamed grant
  await post(plain, [['client', 'Snort']]);
  assert.equal(b.grants![plain].name, 'Coracle'); assert.equal(changes, 2);
  assert.equal(b.scopes?.[plain], undefined);

  // With nothing typed and the switches left off, the note says so and the site has no name yet.
  call({ call: 'note_put', session, kind: 'bunker', text: '   ' });
  const [n2] = await D.notes(phone, held, send, T);
  assert.deepEqual([n2.lists, n2.dms], [false, false]);
  await D.answerNotes(phone, held, send, can, T);
  assert.deepEqual(asked, { name: undefined, lists: false, dms: false });
  // A site's sign-in code handed over by the page carries the switches too, and the device gets them with the code.
  call({ call: 'note_put', session, kind: 'nostrconnect', text: 'nostrconnect://x', lists: true });
  const nc = (await D.notes(phone, held, send, T)).find((x) => x.kind === 'nostrconnect')!;
  assert.deepEqual([nc.lists, nc.dms], [true, false]);
  let connected: any;
  assert.ok((await D.answerNotes(phone, held, send, { ...can, connect: async (uri: string, o: any) => { connected = [uri, o]; return true; } }, T)).includes('signed a site in'));
  assert.deepEqual(connected, ['nostrconnect://x', { lists: true, dms: false }]);
  // Other kinds of note carry no switches.
  call({ call: 'note_put', session, kind: 'invite', text: '{}', lists: true });
  assert.equal((await D.notes(phone, held, send, T)).find((x) => x.kind === 'invite')!.lists, undefined);
});
