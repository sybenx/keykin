import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as F from '../src/frost.ts';
import { ask, answer, finish, type Piece } from '../src/round.ts';
import { eventId } from '../src/event.ts';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import { sealTo, openFrom } from '../src/seal.ts';
import * as D from '../src/device.ts';
import { Box } from '../box/box.ts';
import { bytesToHex, hexToBytes, randomBytes, sha } from '../src/bytes.ts';
import { mul, compHex } from '../src/curve.ts';
import * as nip44 from 'nostr-tools/nip44';

const NOW = 1_800_000_000;
const valid = (sig: string, msg: string, npub: string) => schnorr.verify(hexToBytes(sig), hexToBytes(msg), hexToBytes(npub));
const note = (npub: string, content = 'hello') => ({ pubkey: npub, created_at: NOW, kind: 1, tags: [], content });
const device = (name: string, withChip = true): D.Me => ({ ...newMemberKey(), name, ...(withChip ? softwareChip() : {}) });

// A phone scans the box's QR and the two make the key together.
async function setup() {
  const box = new Box();
  const send: D.Send = async (r) => box.handle(JSON.parse(JSON.stringify(r)), NOW);
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(box.qr('http://box')!), send, NOW);
  const add = async (name: string, withChip = true) => {
    const me = device(name, withChip);
    await D.addMember(phone, held, { key: me.key, name, kind: 'device', chip: me.chip }, send, NOW);
    return { me, held: await D.join(me, held.boxKey, held.npub, send, NOW) };
  };
  return { box, send, phone, held, add };
}

test('the signing maths: any two pieces of a line sign, one cannot', () => {
  const nsec = bytesToHex(randomBytes(32));
  const { commitment: C, a0, a1 } = F.deal(BigInt('0x' + nsec));
  const npub = bytesToHex(schnorr.getPublicKey(hexToBytes(nsec)));
  const ps: Piece[] = [1, 2, 3, 4, 5].map((i) => ({ C, i, share: F.pieceAt(a0, a1, i) }));
  for (const x of ps) for (const y of ps) {
    if (x === y) continue;
    for (let k = 0; k < 4; k++) {   // several rounds, so both parities of R are met
      const msg = bytesToHex(sha('m', String(x.i), String(y.i), String(k)));
      const mine = ask(x, msg);
      assert.ok(valid(finish(x, msg, mine, answer(y, msg, mine.commit)), msg, npub));
    }
  }
  const msg = bytesToHex(sha('x'));
  const mine = ask(ps[0], msg);
  assert.throws(() => answer(ps[0], msg, mine.commit), /same_piece/);
  const other = answer(ps[1], bytesToHex(sha('y')), mine.commit);
  assert.throws(() => finish(ps[0], msg, mine, { commit: answer(ps[1], msg, mine.commit).commit, z: other.z }), /bad_partial/);
});

test('scan the QR: device and box make the key together, then sign', async () => {
  const { box, send, phone, held } = await setup();
  const acct = box.only()!;
  assert.equal(acct.npub, held.npub);
  assert.equal(box.qr('http://box'), null);                       // no QR once there is an account
  // Each side holds one piece of the same line, and they are different pieces.
  assert.notEqual(acct.share, held.piece.share.toString(16).padStart(64, '0'));
  assert.deepEqual(acct.commitment, held.piece.C.map(compHex));
  const ev = await D.signEvent(phone, held, note(held.npub), send, NOW);
  assert.equal(ev.id, eventId(note(held.npub)));
  assert.ok(valid(ev.sig, ev.id, held.npub));
  assert.deepEqual(acct.members.map((m) => [m.i, m.kind, m.name]), [[1, 'device', 'Phone'], [2, 'box', 'Box']]);
});

test('creating needs the code from the QR, and happens once', async () => {
  const box = new Box();
  const send: D.Send = async (r) => box.handle(r, NOW);
  const qr = D.readQr(box.qr('http://box')!);
  await assert.rejects(D.createWithBox(device('Thief'), { ...qr, code: 'nope' }, send, NOW), /bad_code/);
  await D.createWithBox(device('Phone'), qr, send, NOW);
  await assert.rejects(D.createWithBox(device('Late'), qr, send, NOW), /already_set_up/);
  assert.throws(() => D.readQr('{"keykin":1}'), /bad_qr/);
});

test('a device given the wrong box key in the QR cannot finish creating', async () => {
  const box = new Box();
  const send: D.Send = async (r) => box.handle(r, NOW);
  const qr = D.readQr(box.qr('http://box')!);
  await assert.rejects(D.createWithBox(device('Phone'), { ...qr, key: newMemberKey().key }, send, NOW), /bad_seal/);
  assert.equal(box.only(), null);
});

test('adding a device: it gets a working piece and nobody held the key', async () => {
  const { send, phone, held, add } = await setup();
  const laptop = await add('Laptop');
  assert.equal(laptop.held.piece.i, 3);
  assert.ok(valid((await D.signEvent(laptop.me, laptop.held, note(held.npub), send, NOW)).sig, eventId(note(held.npub)), held.npub));
  // Two devices sign with no box.
  const msg = eventId(note(held.npub, 'no box'));
  const mine = ask(held.piece, msg);
  assert.ok(valid(finish(held.piece, msg, mine, answer(laptop.held.piece, msg, mine.commit)), msg, held.npub));
  // A third device, added by the first; indices only go up.
  const tablet = await add('Tablet');
  assert.equal(tablet.held.piece.i, 4);
  const m2 = ask(tablet.held.piece, msg);
  assert.ok(valid(finish(tablet.held.piece, msg, m2, answer(laptop.held.piece, msg, m2.commit)), msg, held.npub));
  assert.ok(phone);
});

test('account changes need the fingerprint', async () => {
  const { box, send, phone, held, add } = await setup();
  const laptop = await add('Laptop');
  const old = await add('Old tablet', false);                       // no chip in it
  const m = { key: newMemberKey().key, name: 'X', kind: 'device' as const };
  // No fingerprint, a wrong chip, and a device with no chip: all refused.
  await assert.rejects(D.addMember({ ...phone, fp: undefined }, held, m, send, NOW), /needs_fingerprint/);
  await assert.rejects(D.addMember({ ...phone, fp: softwareChip().fp }, held, m, send, NOW), /needs_fingerprint/);
  await assert.rejects(D.addMember(old.me, old.held, m, send, NOW), /no_chip_key/);
  await assert.rejects(D.formNsec({ ...phone, fp: undefined }, held, send, NOW), /needs_fingerprint/);
  await assert.rejects(D.formNsec(old.me, old.held, send, NOW), /no_chip_key/);
  await D.block(old.me, laptop.me.key, send, NOW);                 // blocking needs none
  await assert.rejects(D.unblock({ ...phone, fp: undefined }, laptop.me.key, send, NOW), /needs_fingerprint/);
  await D.unblock(phone, laptop.me.key, send, NOW);
  // A fingerprint signature cannot be moved onto another request.
  const real = await seal({ op: 'unblock', key: laptop.me.key }, phone.sk, NOW, phone.fp);
  const moved = await seal({ op: 'reveal', epoch: 0 }, phone.sk, NOW); moved.fp = real.fp;
  assert.deepEqual(box.handle(moved, NOW), { error: 'needs_fingerprint' });
  assert.equal(box.only()!.members.length, 4);
});

test('falling back to the nsec: a fingerprint forms it on the device, and it is the same key', async () => {
  const { send, phone, held, add } = await setup();
  const nsec = await D.formNsec(phone, held, send, NOW);
  assert.equal(bytesToHex(schnorr.getPublicKey(hexToBytes(nsec))), held.npub);
  assert.equal(compHex(mul(BigInt('0x' + nsec))).slice(2), held.npub);
  const laptop = await add('Laptop');
  assert.equal(await D.formNsec(laptop.me, laptop.held, send, NOW), nsec);
});

test('a blocked phone gets no help, and cannot undo it itself', async () => {
  const { box, send, phone, held, add } = await setup();
  const laptop = await add('Laptop');
  await D.block(laptop.me, phone.key, send, NOW);
  await assert.rejects(D.signEvent(phone, held, note(held.npub), send, NOW), /blocked/);
  await assert.rejects(D.unblock(phone, phone.key, send, NOW), /blocked/);
  await assert.rejects(D.formNsec(phone, held, send, NOW), /blocked/);
  await D.unblock(laptop.me, phone.key, send, NOW);
  await D.signEvent(phone, held, note(held.npub), send, NOW);
  box.ownerBlock(laptop.me.key);                                  // the box owner's button
  await assert.rejects(D.signEvent(laptop.me, laptop.held, note(held.npub), send, NOW), /blocked/);
  assert.throws(() => box.ownerBlock(box.state.key), /cannot_block_box/);
});

test('a thief blocks every other device; the box owner puts it right', async () => {
  const { box, send, phone, held, add } = await setup();
  const laptop = await add('Laptop');
  const tablet = await add('Tablet');
  await D.block(phone, laptop.me.key, send, NOW);                 // the thief holds the phone
  await D.block(phone, tablet.me.key, send, NOW);
  await assert.rejects(D.block(laptop.me, phone.key, send, NOW), /blocked/);   // too late from a device
  box.ownerBlock(phone.key);                                      // the owner, at the box
  box.ownerUnblock(laptop.me.key);
  box.ownerUnblock(tablet.me.key);
  await assert.rejects(D.signEvent(phone, held, note(held.npub), send, NOW), /blocked/);
  await assert.rejects(D.formNsec(phone, held, send, NOW), /blocked/);
  await D.signEvent(laptop.me, laptop.held, note(held.npub), send, NOW);
  await D.signEvent(tablet.me, tablet.held, note(held.npub), send, NOW);
});

test('cycling the keys: a blocked piece stops fitting, the rest catch up, the npub stays', async () => {
  const { box, send, phone, held, add } = await setup();
  const laptop = await add('Laptop');
  const tablet = await add('Tablet');
  const thief = await add('Stolen');
  const msg = eventId(note(held.npub));
  await D.block(phone, thief.me.key, send, NOW);
  await assert.rejects(D.cycle({ ...phone, fp: undefined }, held, send, NOW), /needs_fingerprint/);
  const before = await D.formNsec(phone, held, send, NOW);
  await D.cycle(phone, held, send, NOW);
  const a = box.only()!;
  assert.equal(a.epoch, 1);
  assert.deepEqual(a.members.map((m) => m.name), ['Phone', 'Box', 'Laptop', 'Tablet']);     // the blocked one is gone
  // The stolen piece no longer fits with the box's new piece, even if the box were to answer it.
  const boxPiece = { C: held.piece.C, i: a.i, share: BigInt('0x' + a.share) };
  const stale = ask(thief.held.piece, msg);
  assert.throws(() => finish(thief.held.piece, msg, stale, answer(boxPiece, msg, stale.commit)), /bad_partial|bad_signature/);
  await assert.rejects(D.signEvent(thief.me, thief.held, note(held.npub), send, NOW), /unknown_member/);
  // The one who cycled signs at once; the others catch up on their next request, by themselves.
  assert.ok(valid((await D.signEvent(phone, held, note(held.npub), send, NOW)).sig, msg, held.npub));
  assert.equal(laptop.held.epoch, 0);
  assert.ok(valid((await D.signEvent(laptop.me, laptop.held, note(held.npub), send, NOW)).sig, msg, held.npub));
  assert.equal(laptop.held.epoch, 1);
  assert.equal(a.catchups[laptop.me.key], undefined);
  // A second cycle before the tablet has come back: it catches up on both at once.
  await D.cycle(laptop.me, laptop.held, send, NOW);
  assert.equal(await D.formNsec(tablet.me, tablet.held, send, NOW), before);              // same key throughout
  assert.equal(tablet.held.epoch, 2);
  // Two caught-up devices still sign with no box, and a new device gets an index never used before.
  await D.signEvent(phone, held, note(held.npub), send, NOW);
  const m2 = ask(held.piece, msg);
  assert.ok(valid(finish(held.piece, msg, m2, answer(tablet.held.piece, msg, m2.commit)), msg, held.npub));
  const fresh = await add('New');
  assert.equal(fresh.held.piece.i, 6);                                   // 5 was the stolen one: never reused
  assert.ok(valid((await D.signEvent(fresh.me, fresh.held, note(held.npub), send, NOW)).sig, msg, held.npub));
});

test('the box refuses strangers, other accounts, stale, repeated and altered requests', async () => {
  const { box, send, phone, held } = await setup();
  assert.deepEqual(box.handle(await seal({ op: 'members' }, newMemberKey().sk, NOW), NOW), { error: 'unknown_member' });
  await assert.rejects(D.signEvent(phone, held, note(bytesToHex(randomBytes(32))), send, NOW), /wrong_account/);
  const req = await seal({ op: 'members' }, phone.sk, NOW);
  assert.equal(box.handle(req, NOW).ok, true);
  assert.deepEqual(box.handle(req, NOW), { error: 'replay' });
  assert.deepEqual(box.handle(await seal({ op: 'members' }, phone.sk, NOW - 600), NOW), { error: 'stale' });
  const forged = await seal({ op: 'members' }, phone.sk, NOW); (forged.body as any).op = 'block';
  assert.deepEqual(box.handle(forged, NOW), { error: 'bad_sig' });
});

test('a second box gets a piece but may not ask for a signature', async () => {
  const { box, send, phone, held } = await setup();
  const box2: D.Me = { ...newMemberKey(), name: 'Box 2' };
  await D.addMember(phone, held, { key: box2.key, name: 'Box 2', kind: 'box' }, send, NOW);
  const h2 = await D.join(box2, held.boxKey, held.npub, send, NOW);
  await assert.rejects(D.signEvent(box2, h2, note(held.npub), send, NOW), /devices_only/);
  // But two boxes can sign between themselves (the maths), which is how a second box is a backup.
  const msg = eventId(note(held.npub));
  const a = box.only()!;
  const mine = ask(h2.piece, msg);
  assert.ok(valid(finish(h2.piece, msg, mine, answer({ C: h2.piece.C, i: a.i, share: BigInt('0x' + a.share) }, msg, mine.commit)), msg, held.npub));
});

test('messages: two pieces make the same NIP-44 key the whole nsec would', async () => {
  const { send, phone, held, add } = await setup();
  const friendSk = randomBytes(32);
  const friend = bytesToHex(schnorr.getPublicKey(friendSk));
  const viaPieces = await D.conversationKey(phone, held, friend, send, NOW);
  const nsec = await D.formNsec(phone, held, send, NOW);
  assert.deepEqual(viaPieces, nip44.v2.utils.getConversationKey(hexToBytes(nsec), friend));
  // The friend, with an ordinary key, reads what the pieces wrote and the reverse.
  const friendKey = nip44.v2.utils.getConversationKey(friendSk, held.npub);
  assert.equal(nip44.v2.decrypt(await D.nip44Encrypt(phone, held, friend, 'from pieces', send, NOW), friendKey), 'from pieces');
  const laptop = await add('Laptop');
  assert.equal(await D.nip44Decrypt(laptop.me, laptop.held, friend, nip44.v2.encrypt('to pieces', friendKey), send, NOW), 'to pieces');
  await D.block(phone, laptop.me.key, send, NOW);
  await assert.rejects(D.conversationKey(laptop.me, laptop.held, friend, send, NOW), /blocked/);
});

test('sealed values open only for the right pair and purpose', () => {
  const [a, b, c] = [newMemberKey(), newMemberKey(), newMemberKey()];
  const s = sealTo(a.sk, b.key, 'reveal', 'ab'.repeat(32));
  assert.equal(openFrom(b.sk, a.key, 'reveal', s), 'ab'.repeat(32));
  assert.throws(() => openFrom(c.sk, a.key, 'reveal', s), /bad_seal/);
  assert.throws(() => openFrom(b.sk, a.key, 'keygen', s), /bad_seal/);
});

test('state survives a restart, waiting welcomes included', async () => {
  const { box, phone, held, send } = await setup();
  const late = device('Late');
  await D.addMember(phone, held, { key: late.key, name: 'Late', kind: 'device', chip: late.chip }, send, NOW);
  const again = new Box(JSON.parse(JSON.stringify(box.state)));
  const send2: D.Send = async (r) => again.handle(r, NOW);
  const h = await D.join(late, held.boxKey, held.npub, send2, NOW);
  assert.ok(valid((await D.signEvent(late, h, note(held.npub), send2, NOW)).sig, eventId(note(held.npub)), held.npub));
  assert.deepEqual(again.only()!.welcomes, {});             // cleared once it has signed
  // A newcomer that has not collected its piece holds up a cycle, so it is never stranded.
  const slow = device('Slow');
  await D.addMember(late, h, { key: slow.key, name: 'Slow', kind: 'device', chip: slow.chip }, send2, NOW);
  await assert.rejects(D.cycle(late, h, send2, NOW), /pending_welcome/);
});
