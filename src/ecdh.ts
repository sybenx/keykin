// A shared secret with someone else's Nostr key (what NIP-44 and NIP-04 messages need), made by two
// pieces without the key being whole. Each piece gives `λ_i · s_i · Q` for the other person's key
// `Q`; the two parts add up to `nsec · Q`. One part alone says nothing useful.

import { extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { lagrange, liftX, mul, compHex, pointFrom, mod } from './curve.ts';
import { hexToBytes, utf8ToBytes, refuse } from './bytes.ts';

/** This piece's part for the peer `Q` (x-only hex), when signing with the piece at `other`. */
export function ecdhPart(i: number, share: bigint, other: number, peer: string): string {
  if (!/^[0-9a-f]{64}$/.test(peer)) refuse('bad_peer');
  const l = lagrange(BigInt(i), [BigInt(i), BigInt(other)]);
  return compHex(mul(mod(l * share), liftX(peer)));
}

/** The shared x coordinate from the two parts. */
export function ecdhShared(a: string, b: string): string {
  const p = pointFrom(a).add(pointFrom(b));
  if (p.is0()) refuse('bad_part');
  return compHex(p).slice(2);
}

/** The NIP-44 v2 conversation key for a shared x. */
export const nip44Key = (sharedX: string) => extract(sha256, hexToBytes(sharedX), utf8ToBytes('nip44-v2'));
