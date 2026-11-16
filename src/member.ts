// Member keys and signed requests. Every piece holder has a member key (secp256k1, x-only). A
// request is `{ body, key, sig }`: `sig` is a BIP-340 signature by `key` over SHA-256(JCS(body)).
// `body.ts` (unix seconds) and `body.id` (random) let the receiver refuse stale and repeated ones.
//
// The fingerprint. A device may also have a **chip key**: a P-256 key inside the phone's secure
// chip, which signs only after a fingerprint or face check. Account changes carry `fp`, an ECDSA
// (SHA-256) signature by the chip key over the same JCS(body). The receiver checks it against the
// chip key on the member list. Here the chip is whatever `Fingerprint` function the caller gives.

import { schnorr } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { sha, jcsBytes, randomBytes, bytesToHex, hexToBytes, refuse } from './bytes.ts';

export interface Signed<B = any> { body: B; key: string; sig: string; fp?: string }
/** Asks the chip to sign. On a phone this is where the fingerprint prompt appears. */
export type Fingerprint = (message: Uint8Array) => Promise<string> | string;
export const MAX_SKEW = 60;

export const newMemberKey = () => { const sk = randomBytes(32); return { sk: bytesToHex(sk), key: bytesToHex(schnorr.getPublicKey(sk)) }; };

/** A software stand-in for the chip, for tests and for machines with no chip. */
export function softwareChip() {
  const sk = p256.utils.randomSecretKey();
  const fp: Fingerprint = (m) => bytesToHex(p256.sign(m, sk));
  return { chip: bytesToHex(p256.getPublicKey(sk, true)), fp };
}

export async function seal<B extends object>(body: B, sk: string, now: number, fp?: Fingerprint): Promise<Signed<B & { ts: number; id: string }>> {
  const full = { ...body, ts: now, id: bytesToHex(randomBytes(16)) };
  const bytes = jcsBytes(full);
  const key = bytesToHex(schnorr.getPublicKey(hexToBytes(sk)));
  const out: Signed<B & { ts: number; id: string }> = { body: full, key, sig: bytesToHex(schnorr.sign(sha(bytes), hexToBytes(sk))) };
  if (fp) out.fp = await fp(bytes);
  return out;
}

/** Returns the body if the signature holds and the request is fresh; throws otherwise. */
export function open<B = any>(r: Signed<B>, now: number): B & { ts: number; id: string } {
  const b = r?.body as any;
  if (!b || typeof r.key !== 'string' || typeof r.sig !== 'string') refuse('bad_request');
  if (!/^[0-9a-f]{64}$/.test(r.key) || !/^[0-9a-f]{128}$/.test(r.sig)) refuse('bad_request');
  if (!Number.isInteger(b.ts) || typeof b.id !== 'string') refuse('bad_request');
  if (Math.abs(now - b.ts) > MAX_SKEW) refuse('stale');
  if (!schnorr.verify(hexToBytes(r.sig), sha(jcsBytes(b)), hexToBytes(r.key))) refuse('bad_sig');
  return b;
}

/** True if the request carries a valid fingerprint signature by `chip` (33-byte P-256 key, hex). */
export function fingerprintOk(r: Signed, chip: string | undefined): boolean {
  if (!chip || typeof r.fp !== 'string') return false;
  try { return p256.verify(hexToBytes(r.fp), jcsBytes(r.body), hexToBytes(chip), { lowS: false }); } catch { return false; }
}
