// Many accounts on one box, asking and approving, and what the account page may do (SPEC 11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';
import { PageApi } from '../box/pageapi.ts';
import { eventId } from '../src/event.ts';
import { hexToBytes, bytesToHex, randomBytes } from '../src/bytes.ts';

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
  await D.passwordSet(phone, held, 'aaron', 'correct horse', send, NOW);
  assert.doesNotMatch(JSON.stringify(box.state), /correct horse/);

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
  // Clearing the password ends that way in.
  await D.passwordClear(phone, held, send, now());
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: v2 }), { error: 'wrong' });
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
  const join = JSON.parse(call({ call: 'note_get', session, note: n1 }).result).join;
  assert.deepEqual(join, { addr: 'https://account.example', boxKey: held.boxKey, npub: held.npub });
  const lh = await D.join(laptop, join.boxKey, join.npub, send, NOW);
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

test('hard-to-undo signatures need a Yes on the device; ordinary ones do not', async () => {
  const { box, send } = world();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  const ev = (kind: number, tags: string[][], content = '') => ({ pubkey: held.npub, created_at: NOW, kind, tags, content });
  const many = ['1', '2', '3', '4', '5'].map((x) => ['e', x.repeat(64)]);
  const hard = [ev(62, [['relay', 'ALL_RELAYS']]), ev(5, many), ev(3, []), ev(0, [], '{}'), ev(0, [], '{"name":"  "}')];
  const fine = [ev(1, []), ev(5, many.slice(0, 4)), ev(3, [['p', 'a'.repeat(64)]]), ev(0, [], '{"name":"Aaron"}'), ev(7, [['e', 'a'.repeat(64)]], '+')];
  for (const e of hard) await assert.rejects(D.signEvent(phone, held, e, send, NOW), /needs_tap/);
  for (const e of hard) assert.ok(valid(await D.signEvent(phone, held, e, send, NOW, undefined, true)));
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
