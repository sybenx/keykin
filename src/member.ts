// Member keys and signed requests. Every piece holder has a member key (secp256k1, x-only). A
// request is `{ body, key, sig }`: `sig` is a BIP-340 signature by `key` over SHA-256(JCS(body)).
// `body.ts` (unix seconds) and `body.id` (random) let the receiver refuse stale and repeated ones.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha, jcsBytes, randomBytes, bytesToHex, hexToBytes, refuse } from './bytes.ts';

export interface Signed<B = any> { body: B; key: string; sig: string }
export const MAX_SKEW = 60;

export const newMemberKey = () => { const sk = randomBytes(32); return { sk: bytesToHex(sk), key: bytesToHex(schnorr.getPublicKey(sk)) }; };

export function seal<B extends object>(body: B, sk: string, now: number): Signed<B & { ts: number; id: string }> {
  const full = { ...body, ts: now, id: bytesToHex(randomBytes(16)) };
  const key = bytesToHex(schnorr.getPublicKey(hexToBytes(sk)));
  return { body: full, key, sig: bytesToHex(schnorr.sign(sha(jcsBytes(full)), hexToBytes(sk))) };
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
