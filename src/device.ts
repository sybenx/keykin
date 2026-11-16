// A device's side of everything. `send` carries a signed request to the box and returns its reply;
// over HTTP, a tailnet or a test bus, this file does not care.

import * as F from './frost.ts';
import { ask, finish, type Piece } from './round.ts';
import { eventId, type UnsignedEvent } from './event.ts';
import { seal, type Signed, type Fingerprint } from './member.ts';
import { sealTo, openFrom } from './seal.ts';
import { commitmentFrom, scalarFrom, scalarHex, interpolate, mul, compHex } from './curve.ts';
import { refuse } from './bytes.ts';

export type Send = (req: Signed) => Promise<any>;
/** This device: its member key, and its chip (fingerprint) if it has one. */
export interface Me { sk: string; key: string; name: string; chip?: string; fp?: Fingerprint }
/** What a device keeps once it is in an account. */
export interface Held { piece: Piece; npub: string; boxKey: string }

const call = async (send: Send, req: Signed) => { const r = await send(req); if (r?.error) refuse(r.error); return r; };
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
  return { piece: { C: done.C, i: 1, share: done.share }, npub: done.npub, boxKey: qr.key };
}

export async function signEvent(me: Me, h: Held, ev: UnsignedEvent, send: Send, t = now()) {
  const id = eventId(ev);
  const mine = ask(h.piece, id);
  const r = await call(send, await seal({ op: 'sign', event: ev, commit: mine.commit }, me.sk, t));
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
  const i = Math.max(...list.members.map((x: any) => x.i)) + 1;
  const boxI = list.members.find((x: any) => x.key === h.boxKey)?.i ?? refuse('no_box');
  const helpers = [h.piece.i, boxI].sort((a, b) => a - b);
  const mine = F.repairDeltas(h.piece.C, helpers, h.piece.i, h.piece.share, i);
  const r = await call(send, await seal({ op: 'add', member: { ...m, i }, delta: sealTo(me.sk, h.boxKey, 'repair-delta', mine.get(boxI)!) }, me.sk, t, me.fp));
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
  return { piece: { C, i: r.i, share: F.repairShare(C, sigmas, r.i) }, npub, boxKey };
}

/**
 * Falls back to the nsec. Needs the fingerprint. The box hands over its piece, and this device
 * forms the nsec from the two. This is the only place a whole key ever exists.
 */
export async function formNsec(me: Me, h: Held, send: Send, t = now()): Promise<string> {
  const r = await call(send, await seal({ op: 'reveal' }, me.sk, t, me.fp));
  const boxShare = scalarFrom(openFrom(me.sk, h.boxKey, 'reveal', r.share));
  const nsec = interpolate([[BigInt(h.piece.i), h.piece.share], [BigInt(r.i), boxShare]], 0n);
  if (compHex(mul(nsec)).slice(2) !== h.npub) refuse('bad_piece');
  return scalarHex(nsec);
}
