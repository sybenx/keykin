import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import { createAccount, issuePiece, commitmentOf, type Account } from '../src/account.ts';
import { ask, answer, finish, type Piece } from '../src/round.ts';
import { eventId } from '../src/event.ts';
import { newMemberKey, seal } from '../src/member.ts';
import { signEvent } from '../src/device.ts';
import { Box } from '../box/box.ts';
import { bytesToHex, hexToBytes, randomBytes, sha } from '../src/bytes.ts';
import { scalarHex } from '../src/curve.ts';

const NOW = 1_800_000_000;
const piece = (a: Account): Piece => ({ C: a.C, ...issuePiece(a) });
const valid = (sig: string, msg: string, npub: string) => schnorr.verify(hexToBytes(sig), hexToBytes(msg), hexToBytes(npub));
const note = (npub: string, content = 'hello') => ({ pubkey: npub, created_at: NOW, kind: 1, tags: [], content });

test('any two pieces sign, under the same npub as the imported nsec', () => {
  const nsec = bytesToHex(randomBytes(32));
  const a = createAccount(nsec);
  assert.equal(a.npub, bytesToHex(schnorr.getPublicKey(hexToBytes(nsec))));
  const ps = [piece(a), piece(a), piece(a), piece(a), piece(a)];
  for (let x = 0; x < ps.length; x++) for (let y = 0; y < ps.length; y++) {
    if (x === y) continue;
    for (let k = 0; k < 4; k++) {   // several rounds, so both parities of R are met
      const msg = bytesToHex(sha('m', String(x), String(y), String(k)));
      const mine = ask(ps[x], msg);
      assert.ok(valid(finish(ps[x], msg, mine, answer(ps[y], msg, mine.commit)), msg, a.npub));
    }
  }
});

test('one piece alone signs nothing, and a wrong partial is refused', () => {
  const a = createAccount();
  const [p1, p2] = [piece(a), piece(a)];
  const msg = bytesToHex(sha('x'));
  const mine = ask(p1, msg);
  assert.throws(() => answer(p1, msg, mine.commit), /same_piece/);
  const ans = answer(p2, msg, mine.commit);
  const other = answer(p2, bytesToHex(sha('y')), mine.commit);
  assert.throws(() => finish(p1, msg, mine, { commit: ans.commit, z: other.z }), /bad_partial/);
});

function setup() {
  const a = createAccount();
  const phone = { p: piece(a), ...newMemberKey() };
  const boxPiece = issuePiece(a);
  const boxKey = newMemberKey();
  const box = new Box('code-123');
  const send = async (r: any) => box.handle(JSON.parse(JSON.stringify(r)), NOW);
  const r = box.handle(seal({ op: 'setup', code: 'code-123', commitment: commitmentOf(a), i: boxPiece.i, share: scalarHex(boxPiece.share),
    boxKey: boxKey.key, deviceIndex: phone.p.i, deviceName: 'Phone' }, phone.sk, NOW), NOW);
  assert.deepEqual(r, { ok: true, npub: a.npub });
  const addDevice = (name: string) => {
    const d = { p: piece(a), ...newMemberKey() };
    assert.deepEqual(box.handle(seal({ op: 'add', member: { key: d.key, i: d.p.i, name, kind: 'device' } }, phone.sk, NOW), NOW), { ok: true });
    return d;
  };
  return { a, phone, box, send, addDevice };
}

test('phone plus the box signs a Nostr event', async () => {
  const { a, phone, send } = setup();
  const ev = await signEvent(phone.p, phone.sk, note(a.npub), send, NOW);
  assert.equal(ev.id, eventId(note(a.npub)));
  assert.ok(valid(ev.sig, ev.id, a.npub));
});

test('setup needs the code and happens once', () => {
  const a = createAccount();
  const k = newMemberKey(); const bp = issuePiece(a);
  const body = { op: 'setup', code: 'nope', commitment: commitmentOf(a), i: bp.i, share: scalarHex(bp.share), boxKey: newMemberKey().key, deviceIndex: 9 };
  const box = new Box('right');
  assert.deepEqual(box.handle(seal(body, k.sk, NOW), NOW), { error: 'bad_code' });
  assert.equal(box.handle(seal({ ...body, code: 'right' }, k.sk, NOW), NOW).ok, true);
  assert.deepEqual(box.handle(seal({ ...body, code: 'right' }, k.sk, NOW), NOW), { error: 'already_set_up' });
});

test('the box refuses strangers, other accounts, stale and repeated requests', async () => {
  const { a, phone, box, send } = setup();
  const stranger = newMemberKey();
  assert.deepEqual(box.handle(seal({ op: 'members' }, stranger.sk, NOW), NOW), { error: 'unknown_member' });
  const other = createAccount();
  await assert.rejects(signEvent(phone.p, phone.sk, note(other.npub), send, NOW), /wrong_account/);
  const req = seal({ op: 'members' }, phone.sk, NOW);
  assert.equal(box.handle(req, NOW).ok, true);
  assert.deepEqual(box.handle(req, NOW), { error: 'replay' });
  assert.deepEqual(box.handle(seal({ op: 'members' }, phone.sk, NOW - 600), NOW), { error: 'stale' });
  const forged = seal({ op: 'members' }, phone.sk, NOW); (forged.body as any).op = 'block';
  assert.deepEqual(box.handle(forged, NOW), { error: 'bad_sig' });
  assert.ok(a);
});

test('a blocked phone gets no help; unblocking needs another device', async () => {
  const { a, phone, box, send, addDevice } = setup();
  const laptop = addDevice('Laptop');
  await signEvent(laptop.p, laptop.sk, note(a.npub), send, NOW);
  // One press, from any device on the list.
  assert.deepEqual(box.handle(seal({ op: 'block', key: phone.key }, laptop.sk, NOW), NOW), { ok: true });
  await assert.rejects(signEvent(phone.p, phone.sk, note(a.npub), send, NOW), /blocked/);
  assert.deepEqual(box.handle(seal({ op: 'unblock', key: phone.key }, phone.sk, NOW), NOW), { error: 'blocked' });
  assert.deepEqual(box.handle(seal({ op: 'unblock', key: phone.key }, laptop.sk, NOW), NOW), { ok: true });
  await signEvent(phone.p, phone.sk, note(a.npub), send, NOW);
  // The box owner's button.
  box.ownerBlock(laptop.key);
  await assert.rejects(signEvent(laptop.p, laptop.sk, note(a.npub), send, NOW), /blocked/);
  assert.throws(() => box.ownerBlock(box.state!.members.find((m) => m.kind === 'box')!.key), /cannot_block_box/);
});

test('two devices sign with no box, and the box never asks', async () => {
  const { a, phone, box, addDevice } = setup();
  const laptop = addDevice('Laptop');
  const msg = eventId(note(a.npub, 'no box'));
  const mine = ask(phone.p, msg);
  assert.ok(valid(finish(phone.p, msg, mine, answer(laptop.p, msg, mine.commit)), msg, a.npub));
  // A second box is on the list but may not start a signature.
  const box2 = { ...newMemberKey(), ...issuePiece(a) };
  box.handle(seal({ op: 'add', member: { key: box2.key, i: box2.i, name: 'Box 2', kind: 'box' } }, phone.sk, NOW), NOW);
  const m2 = ask({ C: a.C, i: box2.i, share: box2.share }, msg);
  assert.deepEqual(box.handle(seal({ op: 'sign', event: note(a.npub, 'no box'), commit: m2.commit }, box2.sk, NOW), NOW), { error: 'devices_only' });
});

test('state survives a restart', async () => {
  const { a, phone, box } = setup();
  const again = new Box('x', JSON.parse(JSON.stringify(box.state)));
  const ev = await signEvent(phone.p, phone.sk, note(a.npub), async (r) => again.handle(r, NOW), NOW);
  assert.ok(valid(ev.sig, ev.id, a.npub));
});
