// Child keys (SPEC 8k). A child is the account's key plus a number, the tweak `t`: its nsec would be
// `a0 + t`, and nobody ever holds that either. Every piece of the account becomes a piece of the child
// by adding `t` to it, so the same two pieces that sign for the account sign for the child, and no new
// keys are made or backed up.
//
// The tweak is made by two pieces together: the shared secret between the account's key and a point
// that the child's label hashes to. One piece alone cannot work it out, and any two pieces get the
// same answer, on any device, after any number of key cycles.

import { sha, bytesToHex, utf8ToBytes, refuse } from './bytes.ts';
import { type Commitment, Point, mod, mul, N, xOnly, scalarFrom } from './curve.ts';
import type { Piece } from './round.ts';

/** A child as a device keeps it. `t` is the tweak, hex; `npub` is the child's public key, hex. */
export interface Child { label: string; t: string; npub: string }

const label = (l: unknown): Uint8Array => {
  if (typeof l !== 'string') refuse('bad_label');
  const b = utf8ToBytes(l as string);
  if (b.length < 1 || b.length > 100) refuse('bad_label');
  return b;
};

/** The point a label stands for, as an x-only key: the first hash that is the x of a point. */
export function labelPoint(l: string): string {
  const b = label(l);
  for (let n = 0; n < 256; n++) {
    const x = bytesToHex(sha('keykin2-child-point', Uint8Array.of(n), b));
    try { Point.fromHex('02' + x); return x; } catch { /* about half of all x are not on the curve */ }
  }
  return refuse('bad_label');
}

/** The tweak for a label, from the shared x of the account's key and `labelPoint(label)`. */
export function tweakFrom(sharedX: string, l: string): string {
  if (!/^[0-9a-f]{64}$/.test(sharedX)) refuse('bad_part');
  const t = mod(BigInt('0x' + bytesToHex(sha('keykin2-child', sharedX, label(l)))));
  if (t === 0n) refuse('bad_child');
  return t.toString(16).padStart(64, '0');
}

/** A tweak that came over the wire: 32 bytes of hex, in range and not zero. */
export function tweakOf(h: unknown): bigint {
  let t: bigint;
  try { t = scalarFrom(h as string, 'child'); } catch { return refuse('bad_child'); }
  if (t === 0n) refuse('bad_child');
  return t;
}

/** The child's line: the account's line moved up by `t`, and turned over if the child's key has odd y. */
function shifted(C: Commitment, t: bigint): { C: Commitment; flip: boolean } {
  const C0 = C[0].add(mul(t));
  if (C0.is0()) refuse('bad_child');
  const flip = C0.toAffine().y % 2n === 1n;
  return { C: flip ? [C0.negate(), ...C.slice(1).map((c) => c.negate())] : [C0, ...C.slice(1)], flip };
}

/** The child's public key (x-only hex) for an account's commitment. Anyone holding `t` can work it out. */
export const childNpub = (C: Commitment, t: bigint): string => xOnly(shifted(C, t).C[0]);

/** This holder's piece of the child. It signs and makes message keys exactly as a piece of the account does. */
export function childPiece(p: Piece, t: bigint): Piece {
  const s = shifted(p.C, t);
  const share = mod(p.share + t);
  return { C: s.C, i: p.i, share: s.flip ? mod(N - share) : share };
}
