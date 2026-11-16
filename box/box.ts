// The box: one always-on machine holding one piece. It never starts a signature; it only helps a
// device that asks. It keeps the list of pieces and refuses blocked ones. No I/O here: `handle`
// takes a request and the time, and `state` is plain JSON the server file saves.

import * as F from '../src/frost.ts';
import { answer } from '../src/round.ts';
import { ecdhPart } from '../src/ecdh.ts';
import { eventId, type UnsignedEvent } from '../src/event.ts';
import { open, fingerprintOk, newMemberKey, type Signed, MAX_SKEW } from '../src/member.ts';
import { sealTo, openFrom } from '../src/seal.ts';
import { commitmentFrom, commitmentHex, scalarHex, scalarFrom, mul, mod, type Commitment } from '../src/curve.ts';
import { KeykinError, refuse, randomBytes, bytesToHex } from '../src/bytes.ts';

export interface Member { key: string; i: number; name: string; kind: 'device' | 'box'; chip?: string; blocked: boolean; added: number }
/** What waits for a newly added member: the two values its piece is built from. */
export interface Welcome { by: string; box: string; device?: string; fetched?: boolean }
/** A change of piece waiting for a member that was not there when the keys were cycled. */
export interface Catchup { from: string; sealed: string }
export interface Account {
  commitment: string[]; npub: string;
  i: number; share: string;            // the box's own piece
  epoch: number;                       // goes up each time the keys are cycled
  next: number;                        // the next unused index
  members: Member[];
  welcomes: Record<string, Welcome>;
  catchups: Record<string, Catchup[]>;
}
/** `owner` is the hash of the owner secret that logs in to the page. */
export interface BoxState { sk: string; key: string; owner?: string; account: Account | null }

const HEX64 = /^[0-9a-f]{64}$/, CHIP = /^0[23][0-9a-f]{64}$/;
const DEVICE_I = 1, BOX_I = 2;         // the first device and the box, at creation
const EPOCH_OPS = new Set(['sign', 'ecdh', 'add', 'reveal', 'cycle']);

export class Box {
  state: BoxState;
  /** Shown as a QR while the box has no account. A fresh one each start. */
  readonly setupCode = bytesToHex(randomBytes(16));
  #seen = new Map<string, number>();   // request id -> ts, for replay refusal
  #pending: { device: string; secret: string; pkg: string; name: string; chip?: string } | null = null;
  onChange: (s: BoxState) => void = () => {};

  constructor(state: BoxState | null = null) { this.state = state ?? { ...newMemberKey(), account: null }; }

  /** What the QR on an empty box says. `addr` is where devices reach it. */
  qr(addr: string) { return this.state.account ? null : JSON.stringify({ keykin: 2, addr, key: this.state.key, code: this.setupCode }); }

  /** Every request comes through here. Returns `{ ok, ... }` or `{ error }`. */
  handle(req: Signed, now: number): any {
    try {
      const body = open(req, now);
      for (const [id, ts] of this.#seen) if (now - ts > 2 * MAX_SKEW) this.#seen.delete(id);
      if (this.#seen.has(body.id)) refuse('replay');
      this.#seen.set(body.id, body.ts);
      if (body.op === 'create1') return this.#create1(body, req.key);
      if (body.op === 'create2') return this.#create2(body, req.key, now);
      const s = this.state.account ?? refuse('not_set_up');
      const from = s.members.find((m) => m.key === req.key) ?? refuse('unknown_member');
      if (from.blocked) refuse('blocked');
      // A device still on the old pieces is told so, and handed what it needs to catch up.
      if (EPOCH_OPS.has(body.op) && body.epoch !== s.epoch) {
        return { error: 'stale', epoch: s.epoch, commitment: s.commitment, catchups: s.catchups[from.key] ?? [] };
      }
      switch (body.op) {
        case 'cycle': return this.#cycle(s, from, req, body);
        case 'caught_up': if (s.catchups[from.key]) { delete s.catchups[from.key]; this.#save(); } return { ok: true };
        case 'sign': return this.#sign(s, from, body);
        case 'ecdh': return this.#ecdh(s, from, body);
        case 'members': return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, next: s.next, boxKey: this.state.key, members: s.members };
        case 'block': return this.#block(s, body.key);
        case 'unblock': return this.#unblock(s, from, req, body.key);
        case 'add': return this.#add(s, from, req, body, now);
        case 'welcome_put': return this.#welcomePut(s, from, body);
        case 'welcome': return this.#welcome(s, from);
        case 'reveal': return this.#reveal(s, from, req);
        default: return refuse('unknown_op');
      }
    } catch (e) {
      if (e instanceof KeykinError) return { error: e.code };
      throw e;
    }
  }

  /** The box owner's Block button (the login page calls this once the owner is logged in). */
  ownerBlock(key: string) { return this.#block(this.state.account ?? refuse('not_set_up'), key); }

  /**
   * The box owner's Unblock button. This is the way back when a thief with an unlocked phone has
   * blocked every other device: the owner logs in to the box, blocks the phone and unblocks the rest.
   */
  ownerUnblock(key: string) {
    const s = this.state.account ?? refuse('not_set_up');
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    m.blocked = false;
    this.#save();
    return { ok: true };
  }

  #save() { this.onChange(this.state); }
  #C(s: Account): Commitment { return commitmentFrom(s.commitment); }

  // Account changes need the fingerprint: a signature by the asking device's chip key.
  #needFingerprint(from: Member, req: Signed) {
    if (from.kind !== 'device') refuse('devices_only');
    if (!from.chip) refuse('no_chip_key');
    if (!fingerprintOk(req, from.chip)) refuse('needs_fingerprint');
  }

  // --- Making the key with the first device. Neither side ever holds the whole key. ---------

  #create1(body: any, device: string) {
    if (this.state.account) refuse('already_set_up');
    if (typeof body.code !== 'string' || body.code !== this.setupCode) refuse('bad_code');
    if (typeof body.pkg !== 'string') refuse('bad_keygen');
    if (body.chip !== undefined && !CHIP.test(body.chip)) refuse('bad_chip_key');
    const mine = F.dkg1(BOX_I, 2);
    this.#pending = { device, secret: mine.secret, pkg: body.pkg, name: String(body.name ?? 'First device'), chip: body.chip };
    return { ok: true, pkg: mine.pkg };
  }

  #create2(body: any, device: string, now: number) {
    if (this.state.account) refuse('already_set_up');
    const p = this.#pending;
    if (!p || p.device !== device) refuse('no_keygen');
    const theirs: [number, string][] = [[DEVICE_I, p!.pkg]];
    let out;
    try {
      const two = F.dkg2(p!.secret, theirs);
      const done = F.dkg3(two.secret, theirs, [[DEVICE_I, openFrom(this.state.sk, device, 'keygen', body.pkg2)]]);
      out = { done, forDevice: two.pkgs.get(DEVICE_I)! };
    } catch (e) { if (e instanceof KeykinError) throw e; return refuse('bad_keygen'); }
    this.#pending = null;
    this.state.account = {
      commitment: commitmentHex(out.done.C), npub: out.done.npub, i: BOX_I, share: scalarHex(out.done.share),
      members: [
        { key: device, i: DEVICE_I, name: p!.name, kind: 'device', chip: p!.chip, blocked: false, added: now },
        { key: this.state.key, i: BOX_I, name: 'Box', kind: 'box', blocked: false, added: now },
      ],
      welcomes: {}, catchups: {}, epoch: 0, next: 3,
    };
    this.#save();
    return { ok: true, npub: out.done.npub, pkg2: sealTo(this.state.sk, device, 'keygen', out.forDevice) };
  }

  // --- Signing ------------------------------------------------------------------------------

  #sign(s: Account, from: Member, body: any) {
    if (from.kind !== 'device') refuse('devices_only');
    const ev = body.event as UnsignedEvent;
    const msg = eventId(ev);
    if (ev.pubkey !== s.npub) refuse('wrong_account');
    const c = body.commit;
    if (!c || c.i !== from.i || typeof c.D !== 'string' || typeof c.E !== 'string') refuse('bad_commit');
    const a = answer({ C: this.#C(s), i: s.i, share: BigInt('0x' + s.share) }, msg, c);
    if (s.welcomes[from.key]) { delete s.welcomes[from.key]; this.#save(); }   // it has its piece
    return { ok: true, id: msg, commit: a.commit, z: a.z };
  }

  // The box's part of a shared secret with another person's key, for encrypting and decrypting
  // messages. It is useless without the asking device's own part.
  #ecdh(s: Account, from: Member, body: any) {
    if (from.kind !== 'device') refuse('devices_only');
    return { ok: true, i: s.i, part: ecdhPart(s.i, BigInt('0x' + s.share), from.i, body.peer) };
  }

  // --- The list -----------------------------------------------------------------------------

  // Blocking is one press and anyone on the list may do it. Undoing it is the hard direction.
  #block(s: Account, key: string) {
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    if (m.kind === 'box') refuse('cannot_block_box');
    m.blocked = true;
    delete s.welcomes[m.key];
    this.#save();
    return { ok: true };
  }

  #unblock(s: Account, from: Member, req: Signed, key: string) {
    this.#needFingerprint(from, req);
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    m.blocked = false;
    this.#save();
    return { ok: true };
  }

  // Adding a member. The asking device and the box each hold a piece; together they make the piece
  // for a new index without either seeing it and without the key ever being whole. The box's half
  // waits here, sealed to the new member; the device's half arrives with `welcome_put`.
  #add(s: Account, from: Member, req: Signed, body: any, now: number) {
    this.#needFingerprint(from, req);
    const m = body.member;
    if (!m || !HEX64.test(m.key) || !Number.isInteger(m.i) || m.i < 1) refuse('bad_member');
    if (m.kind !== 'device' && m.kind !== 'box') refuse('bad_member');
    if (m.chip !== undefined && !CHIP.test(m.chip)) refuse('bad_chip_key');
    if (m.i !== s.next || s.members.some((x) => x.key === m.key)) refuse('already_listed');   // indices are never reused
    s.next++;
    const helpers = [from.i, s.i].sort((a, b) => a - b);
    const mine = F.repairDeltas(this.#C(s), helpers, s.i, BigInt('0x' + s.share), m.i);
    const sigma = F.repairSigma([mine.get(s.i)!, openFrom(this.state.sk, from.key, 'repair-delta', body.delta)]);
    s.members.push({ key: m.key, i: m.i, name: String(m.name ?? 'Device'), kind: m.kind, chip: m.chip, blocked: false, added: now });
    s.welcomes[m.key] = { by: from.key, box: sealTo(this.state.sk, m.key, 'repair-sigma', sigma) };
    this.#save();
    return { ok: true, delta: sealTo(this.state.sk, from.key, 'repair-delta', mine.get(from.i)!) };
  }

  #welcomePut(s: Account, from: Member, body: any) {
    const w = s.welcomes[body.key] ?? refuse('no_welcome');
    if (w.by !== from.key) refuse('not_yours');
    if (typeof body.sigma !== 'string') refuse('bad_request');
    w.device = body.sigma;
    this.#save();
    return { ok: true };
  }

  #welcome(s: Account, from: Member) {
    const w = s.welcomes[from.key] ?? refuse('no_welcome');
    if (!w.device) refuse('not_ready');
    if (!w.fetched) { w.fetched = true; this.#save(); }
    return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, i: from.i, box: w.box, from: w.by, device: w.device };
  }

  // --- Cycling the keys --------------------------------------------------------------------------

  // After a block, the pieces are moved to a new line through the same key. Every member still
  // welcome gets a small change to its piece; a blocked member gets none, so its old piece no
  // longer fits with anyone's and it is dropped from the list. The asking device picks the change
  // (one number, `b1`): it sends it to the box sealed, and each other member's share of it sealed
  // to that member. Nobody learns anything about the key from it.
  #cycle(s: Account, from: Member, req: Signed, body: any) {
    this.#needFingerprint(from, req);
    // A newcomer that has not collected its piece yet would be left with halves of the old line.
    if (Object.values(s.welcomes).some((w) => !w.fetched)) refuse('pending_welcome');
    s.welcomes = {};
    const others = s.members.filter((m) => !m.blocked && m.key !== from.key && m.key !== this.state.key);
    const given = body.changes ?? {};
    if (Object.keys(given).length !== others.length || others.some((m) => typeof given[m.key] !== 'string')) refuse('bad_cycle');
    const b1 = scalarFrom(openFrom(this.state.sk, from.key, 'cycle', body.b1));
    if (b1 === 0n) refuse('bad_cycle');
    const C = this.#C(s);
    s.share = scalarHex(mod(BigInt('0x' + s.share) + b1 * BigInt(s.i)));
    s.commitment = commitmentHex([C[0], C[1].add(mul(b1))]);
    s.epoch++;
    s.members = s.members.filter((m) => !m.blocked);
    for (const k of Object.keys(s.catchups)) if (!s.members.some((m) => m.key === k)) delete s.catchups[k];
    for (const m of others) (s.catchups[m.key] ??= []).push({ from: from.key, sealed: given[m.key] });
    this.#save();
    return { ok: true, epoch: s.epoch, commitment: s.commitment };
  }

  // --- Falling back to the nsec --------------------------------------------------------------

  // With a fingerprint, the box hands its piece to that device, sealed. Two pieces are the nsec,
  // so this is the one request that lets a whole key exist, and only on the device that asked.
  #reveal(s: Account, from: Member, req: Signed) {
    this.#needFingerprint(from, req);
    return { ok: true, i: s.i, share: sealTo(this.state.sk, from.key, 'reveal', s.share) };
  }
}
