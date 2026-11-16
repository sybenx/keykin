// A device's side of everything. `send` carries a signed request to the box and returns its reply;
// over HTTP, a tailnet or a test bus, this file does not care.

import * as F from './frost.ts';
import { ask, finish, type Piece } from './round.ts';
import { eventId, type UnsignedEvent } from './event.ts';
import { seal, type Signed, type Fingerprint } from './member.ts';
import { sealTo, openFrom } from './seal.ts';
import { commitmentFrom, scalarFrom, scalarHex, interpolate, mul, compHex, mod, derivePoint } from './curve.ts';
import { randomBytes, bytesToHex } from './bytes.ts';
import { ecdhPart, ecdhShared, nip44Key } from './ecdh.ts';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { refuse } from './bytes.ts';

export type Send = (req: Signed) => Promise<any>;
/** This device: its member key, and its chip (fingerprint) if it has one. */
export interface Me { sk: string; key: string; name: string; chip?: string; fp?: Fingerprint }
/** What a device keeps once it is in an account. */
export interface Held { piece: Piece; npub: string; boxKey: string; epoch: number }

const call = async (send: Send, req: Signed) => { const r = await send(req); if (r?.error) refuse(r.error); return r; };

/**
 * A request that depends on the current pieces. If the keys were cycled while this device was away,
 * the box says `stale` and hands over the changes; the device applies them to `h` and asks again.
 * `h` is changed in place, so the caller saves it afterwards.
 */
async function current(me: Me, h: Held, send: Send, t: number, body: (h: Held) => object, fp?: Fingerprint) {
  for (let tries = 0; ; tries++) {
    const r = await send(await seal({ ...body(h), epoch: h.epoch }, me.sk, t, fp));
    if (r?.error !== 'stale' || tries) { if (r?.error) refuse(r.error); return r; }
    let share = h.piece.share;
    for (const c of r.catchups) share = mod(share + scalarFrom(openFrom(me.sk, c.from, 'cycle', c.sealed)));
    const C = commitmentFrom(r.commitment);
    if (compHex(C[0]).slice(2) !== h.npub || !mul(share).equals(derivePoint(C, BigInt(h.piece.i)))) refuse('bad_piece');
    h.piece = { C, i: h.piece.i, share }; h.epoch = r.epoch;
    await call(send, await seal({ op: 'caught_up' }, me.sk, t));
  }
}
const now = () => Math.floor(Date.now() / 1000);

/** What the QR on an empty box says. */
export function readQr(text: string): { addr: string; key: string; code: string } {
  let q: any; try { q = JSON.parse(text); } catch { return refuse('bad_qr'); }
  if (q?.keykin !== 2 || typeof q.addr !== 'string' || !/^[0-9a-f]{64}$/.test(q.key) || typeof q.code !== 'string') refuse('bad_qr');
  return q;
}

/** After scanning the box's QR: the device and the box make the key together. No whole key exists. */
export async function createWithBox(me: Me, qr: { key: string; code: string }, send: Send, t = now()): Promise<Held> {
  const one = F.dkg1(1, 2);
  const r1 = await call(send, await seal({ op: 'create1', code: qr.code, pkg: one.pkg, name: me.name, chip: me.chip }, me.sk, t));
  const box: [number, string][] = [[2, r1.pkg]];
  const two = F.dkg2(one.secret, box);
  const r2 = await call(send, await seal({ op: 'create2', pkg2: sealTo(me.sk, qr.key, 'keygen', two.pkgs.get(2)!) }, me.sk, t));
  const done = F.dkg3(two.secret, box, [[2, openFrom(me.sk, qr.key, 'keygen', r2.pkg2)]]);
  if (done.npub !== r2.npub) refuse('bad_keygen');
  return { piece: { C: done.C, i: 1, share: done.share }, npub: done.npub, boxKey: qr.key, epoch: 0 };
}

export async function signEvent(me: Me, h: Held, ev: UnsignedEvent, send: Send, t = now()) {
  const id = eventId(ev);
  let mine = ask(h.piece, id);
  const r = await current(me, h, send, t, (h) => ({ op: 'sign', event: ev, commit: (mine = ask(h.piece, id)).commit }));
  if (r.id !== id) refuse('wrong_id');
  return { ...ev, id, sig: finish(h.piece, id, mine, { commit: r.commit, z: r.z }) };
}

export async function members(me: Me, send: Send, t = now()) { return call(send, await seal({ op: 'members' }, me.sk, t)); }
export async function block(me: Me, key: string, send: Send, t = now()) { return call(send, await seal({ op: 'block', key }, me.sk, t)); }
/** Needs the fingerprint. */
export async function unblock(me: Me, key: string, send: Send, t = now()) { return call(send, await seal({ op: 'unblock', key }, me.sk, t, me.fp)); }

/**
 * Adds a device (or a second box). Needs the fingerprint. This device and the box each give half
 * of the newcomer's piece; neither sees the piece, and the key is never whole.
 */
export async function addMember(me: Me, h: Held, m: { key: string; name: string; kind: 'device' | 'box'; chip?: string }, send: Send, t = now()) {
  const list = await members(me, send, t);
  const i: number = list.next;
  const boxI = list.members.find((x: any) => x.key === h.boxKey)?.i ?? refuse('no_box');
  const helpers = [h.piece.i, boxI].sort((a, b) => a - b);
  let mine = new Map<number, string>();
  const r = await current(me, h, send, t, (h) => {
    mine = F.repairDeltas(h.piece.C, helpers, h.piece.i, h.piece.share, i);
    return { op: 'add', member: { ...m, i }, delta: sealTo(me.sk, h.boxKey, 'repair-delta', mine.get(boxI)!) };
  }, me.fp);
  const sigma = F.repairSigma([mine.get(h.piece.i)!, openFrom(me.sk, h.boxKey, 'repair-delta', r.delta)]);
  await call(send, await seal({ op: 'welcome_put', key: m.key, sigma: sealTo(me.sk, m.key, 'repair-sigma', sigma) }, me.sk, t));
  return i;
}

/** The new device's side: collect both halves and build its piece. `npub` must be the one it was told. */
export async function join(me: Me, boxKey: string, npub: string, send: Send, t = now()): Promise<Held> {
  const r = await call(send, await seal({ op: 'welcome' }, me.sk, t));
  if (r.npub !== npub) refuse('wrong_account');
  const C = commitmentFrom(r.commitment);
  if (compHex(C[0]).slice(2) !== npub) refuse('wrong_account');
  const sigmas = [openFrom(me.sk, boxKey, 'repair-sigma', r.box), openFrom(me.sk, r.from, 'repair-sigma', r.device)];
  return { piece: { C, i: r.i, share: F.repairShare(C, sigmas, r.i) }, npub, boxKey, epoch: r.epoch };
}

/**
 * Falls back to the nsec. Needs the fingerprint. The box hands over its piece, and this device
 * forms the nsec from the two. This is the only place a whole key ever exists.
 */
export async function formNsec(me: Me, h: Held, send: Send, t = now()): Promise<string> {
  const r = await current(me, h, send, t, () => ({ op: 'reveal' }), me.fp);
  const boxShare = scalarFrom(openFrom(me.sk, h.boxKey, 'reveal', r.share));
  const nsec = interpolate([[BigInt(h.piece.i), h.piece.share], [BigInt(r.i), boxShare]], 0n);
  if (compHex(mul(nsec)).slice(2) !== h.npub) refuse('bad_piece');
  return scalarHex(nsec);
}

/** The NIP-44 conversation key with `peer` (x-only hex), made with the box. The key is never whole. */
export async function conversationKey(me: Me, h: Held, peer: string, send: Send, t = now()): Promise<Uint8Array> {
  const r = await current(me, h, send, t, () => ({ op: 'ecdh', peer }));
  return nip44Key(ecdhShared(ecdhPart(h.piece.i, h.piece.share, r.i, peer), r.part));
}
export async function nip44Encrypt(me: Me, h: Held, peer: string, text: string, send: Send, t = now()) {
  return nip44.encrypt(text, await conversationKey(me, h, peer, send, t));
}
/** A wrong part from the box cannot forge a message: NIP-44's MAC check fails instead. */
export async function nip44Decrypt(me: Me, h: Held, peer: string, payload: string, send: Send, t = now()) {
  return nip44.decrypt(payload, await conversationKey(me, h, peer, send, t));
}

/**
 * Cycles the keys. Needs the fingerprint. Every blocked device is dropped for good and its piece
 * stops fitting with anyone's. The key itself, and so the npub, does not change.
 */
export async function cycle(me: Me, h: Held, send: Send, t = now()) {
  const list = await members(me, send, t);
  let b1 = 0n;
  const r = await current(me, h, send, t, () => {
    b1 = scalarFrom(bytesToHex(randomBytes(32)));
    const changes: Record<string, string> = {};
    for (const m of list.members) {
      if (m.blocked || m.key === me.key || m.key === h.boxKey) continue;
      changes[m.key] = sealTo(me.sk, m.key, 'cycle', scalarHex(mod(b1 * BigInt(m.i))));
    }
    return { op: 'cycle', b1: sealTo(me.sk, h.boxKey, 'cycle', scalarHex(b1)), changes };
  }, me.fp);
  const C = commitmentFrom(r.commitment);
  const share = mod(h.piece.share + b1 * BigInt(h.piece.i));
  if (!mul(share).equals(derivePoint(C, BigInt(h.piece.i)))) refuse('bad_piece');
  h.piece = { C, i: h.piece.i, share }; h.epoch = r.epoch;
}

/** Logs a browser in to the box's page, from the code that page shows. Needs the fingerprint. */
export async function approveLogin(me: Me, h: Held, text: string, send: Send, t = now()) {
  let q: any; try { q = JSON.parse(text)?.login; } catch { return refuse('bad_qr'); }
  if (!q || typeof q.code !== 'string') refuse('bad_qr');
  if (q.key !== h.boxKey) refuse('wrong_box');          // only this account's own box
  await call(send, await seal({ op: 'login', code: q.code }, me.sk, t, me.fp));
}
