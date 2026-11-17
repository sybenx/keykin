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

  // It may block. It has no call at all for unblock, add, sign, cycle or the key.
  assert.deepEqual(call({ call: 'block', session, key: laptop.key }), { ok: true });
  await assert.rejects(D.signEvent(laptop, lh, note(held.npub), send, NOW), /blocked/);
  for (const c of ['unblock', 'add', 'sign', 'cycle', 'reveal', 'password_set']) assert.deepEqual(call({ call: c, session, key: laptop.key }), { error: 'unknown_call' });
  assert.deepEqual(call({ call: 'block', session, key: box.state.key }), { error: 'cannot_block_box' });
  await D.unblock(phone, laptop.key, send, NOW, held.npub);                    // the way back is a device's fingerprint

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
  // Clearing the password ends that way in.
  await D.passwordClear(phone, held, send, now());
  assert.deepEqual(call({ call: 'pw_login', username: 'aaron', verifier: good }), { error: 'wrong' });
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
