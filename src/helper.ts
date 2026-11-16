// A device helping another device, for when the box is off. Any two pieces sign, so a computer that
// stays on can answer a phone directly. It answers only signing and message keys, only for devices on
// the list it last got from the box, and never a blocked one.

import { answer } from './round.ts';
import { ecdhPart } from './ecdh.ts';
import { eventId, type UnsignedEvent } from './event.ts';
import { open, type Signed, MAX_SKEW } from './member.ts';
import { KeykinError, refuse } from './bytes.ts';
import type { Held } from './device.ts';

export interface Listed { key: string; i: number; kind: string; blocked: boolean }

export class DeviceHelper {
  #seen = new Map<string, number>();
  /** The list as last seen at the box. Kept by the caller; empty means help nobody. */
  list: Listed[] = [];
  readonly held: () => Held;
  readonly myKey: string;
  constructor(held: () => Held, myKey: string) { this.held = held; this.myKey = myKey; }

  handle(req: Signed, now: number): any {
    try {
      const body = open(req, now);
      for (const [id, ts] of this.#seen) if (now - ts > 2 * MAX_SKEW) this.#seen.delete(id);
      if (this.#seen.has(body.id)) refuse('replay');
      this.#seen.set(body.id, body.ts);
      const h = this.held();
      const from = this.list.find((m) => m.key === req.key) ?? refuse('unknown_member');
      if (from.blocked) refuse('blocked');
      if (from.kind !== 'device' || from.key === this.myKey) refuse('devices_only');
      // Both must hold pieces of the same line. A device that missed a cycle needs the box to catch up.
      if (body.epoch !== h.epoch) refuse('stale');
      if (body.op === 'sign') {
        const ev = body.event as UnsignedEvent, msg = eventId(ev);
        if (ev.pubkey !== h.npub) refuse('wrong_account');
        const c = body.commit;
        if (!c || c.i !== from.i || typeof c.D !== 'string' || typeof c.E !== 'string') refuse('bad_commit');
        const a = answer(h.piece, msg, c);
        return { ok: true, id: msg, commit: a.commit, z: a.z };
      }
      if (body.op === 'ecdh') return { ok: true, i: h.piece.i, part: ecdhPart(h.piece.i, h.piece.share, from.i, body.peer) };
      return refuse('needs_box');
    } catch (e) {
      if (e instanceof KeykinError) return { error: e.code };
      throw e;
    }
  }
}
