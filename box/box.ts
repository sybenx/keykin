// The box: one always-on machine holding one piece. It never starts a signature; it only helps a
// device that asks. It keeps the list of pieces and refuses blocked ones. No I/O here: `handle`
// takes a request and the time, and `state` is plain JSON the server file saves.

import { answer } from '../src/round.ts';
import { eventId, type UnsignedEvent } from '../src/event.ts';
import { open, type Signed, MAX_SKEW } from '../src/member.ts';
import { commitmentFrom, compHex } from '../src/curve.ts';
import { KeykinError, refuse } from '../src/bytes.ts';

export interface Member { key: string; i: number; name: string; kind: 'device' | 'box'; blocked: boolean; added: number }
export interface BoxState {
  commitment: string[]; npub: string;
  i: number; share: string;            // the box's own piece
  members: Member[];
}

const HEX64 = /^[0-9a-f]{64}$/;

export class Box {
  state: BoxState | null;
  #seen = new Map<string, number>();   // request id -> ts, for replay refusal
  #setupCode: string;
  onChange: (s: BoxState) => void = () => {};

  constructor(setupCode: string, state: BoxState | null = null) { this.#setupCode = setupCode; this.state = state; }

  /** Every request comes through here. Returns `{ ok, ... }` or `{ error }`. */
  handle(req: Signed, now: number): any {
    try {
      const body = open(req, now);
      for (const [id, ts] of this.#seen) if (now - ts > 2 * MAX_SKEW) this.#seen.delete(id);
      if (this.#seen.has(body.id)) refuse('replay');
      this.#seen.set(body.id, body.ts);
      if (body.op === 'setup') return this.#setup(body, req.key, now);
      const s = this.state ?? refuse('not_set_up');
      const from = s.members.find((m) => m.key === req.key) ?? refuse('unknown_member');
      if (from.blocked) refuse('blocked');
      switch (body.op) {
        case 'sign': return this.#sign(s, from, body);
        case 'members': return { ok: true, npub: s.npub, commitment: s.commitment, members: s.members };
        case 'block': return this.#block(s, body.key);
        case 'unblock': return this.#unblock(s, from, body.key);
        case 'add': return this.#add(s, from, body.member, now);
        default: return refuse('unknown_op');
      }
    } catch (e) {
      if (e instanceof KeykinError) return { error: e.code };
      throw e;
    }
  }

  /** The box owner's Block button (the login page calls this once the owner is logged in). */
  ownerBlock(key: string) { return this.#block(this.state ?? refuse('not_set_up'), key); }

  #save() { this.onChange(this.state!); }

  // First contact from the primary device: the box's piece and the first list, proven by the
  // setup code the box printed when it started.
  #setup(body: any, key: string, now: number) {
    if (this.state) refuse('already_set_up');
    if (typeof body.code !== 'string' || body.code !== this.#setupCode) refuse('bad_code');
    const C = commitmentFrom(body.commitment);
    if (C.length !== 2) refuse('bad_commitment');
    if (!Number.isInteger(body.i) || body.i < 1 || !HEX64.test(body.share)) refuse('bad_piece');
    if (!HEX64.test(body.boxKey) || !Number.isInteger(body.deviceIndex) || body.deviceIndex === body.i) refuse('bad_setup');
    this.state = {
      commitment: body.commitment, npub: compHex(C[0]).slice(2), i: body.i, share: body.share,
      members: [
        { key, i: body.deviceIndex, name: String(body.deviceName ?? 'First device'), kind: 'device', blocked: false, added: now },
        { key: body.boxKey, i: body.i, name: String(body.boxName ?? 'Box'), kind: 'box', blocked: false, added: now },
      ],
    };
    this.#save();
    return { ok: true, npub: this.state.npub };
  }

  #sign(s: BoxState, from: Member, body: any) {
    if (from.kind !== 'device') refuse('devices_only');
    const ev = body.event as UnsignedEvent;
    const msg = eventId(ev);
    if (ev.pubkey !== s.npub) refuse('wrong_account');
    const c = body.commit;
    if (!c || c.i !== from.i || typeof c.D !== 'string' || typeof c.E !== 'string') refuse('bad_commit');
    const a = answer({ C: commitmentFrom(s.commitment), i: s.i, share: BigInt('0x' + s.share) }, msg, c);
    return { ok: true, id: msg, commit: a.commit, z: a.z };
  }

  // Blocking is one press and anyone on the list may do it. Undoing it is the hard direction.
  #block(s: BoxState, key: string) {
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    if (m.kind === 'box') refuse('cannot_block_box');
    m.blocked = true;
    this.#save();
    return { ok: true };
  }

  // Unblocking and adding need a device still in hand. The fingerprint (chip key) check that the
  // direction note requires for these two is NOT built yet: today a device's member key is enough.
  #unblock(s: BoxState, from: Member, key: string) {
    if (from.kind !== 'device') refuse('devices_only');
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    if (m.key === from.key) refuse('not_yourself');
    m.blocked = false;
    this.#save();
    return { ok: true };
  }

  #add(s: BoxState, from: Member, m: any, now: number) {
    if (from.kind !== 'device') refuse('devices_only');
    if (!m || !HEX64.test(m.key) || !Number.isInteger(m.i) || m.i < 1) refuse('bad_member');
    if (m.kind !== 'device' && m.kind !== 'box') refuse('bad_member');
    if (s.members.some((x) => x.key === m.key || x.i === m.i)) refuse('already_listed');
    s.members.push({ key: m.key, i: m.i, name: String(m.name ?? 'Device'), kind: m.kind, blocked: false, added: now });
    this.#save();
    return { ok: true };
  }
}
