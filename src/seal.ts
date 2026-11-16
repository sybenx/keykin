// Secrets between two member keys: ECDH on the member keys, then XChaCha20-Poly1305. Used for the
// few secret values that cross the wire (key-generation packages, repair values, a released piece).
// `why` is bound in, so a value sealed for one purpose cannot be replayed for another.

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha, randomBytes, bytesToHex, hexToBytes, utf8ToBytes, concatBytes, refuse } from './bytes.ts';

const keyFor = (sk: string, peer: string) =>
  sha('keykin2-seal', secp256k1.getSharedSecret(hexToBytes(sk), hexToBytes('02' + peer)).slice(1));

export function sealTo(sk: string, peer: string, why: string, secretHex: string): string {
  const nonce = randomBytes(24);
  return bytesToHex(concatBytes(nonce, xchacha20poly1305(keyFor(sk, peer), nonce, utf8ToBytes(why)).encrypt(hexToBytes(secretHex))));
}

export function openFrom(sk: string, peer: string, why: string, boxHex: string): string {
  try {
    const b = hexToBytes(boxHex);
    return bytesToHex(xchacha20poly1305(keyFor(sk, peer), b.slice(0, 24), utf8ToBytes(why)).decrypt(b.slice(24)));
  } catch { return refuse('bad_seal'); }
}
