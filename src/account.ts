// What the primary device does: make or import the nsec, split it, and hand out pieces. It keeps
// the whole nsec (as the tier 1 QRST backup) until the person chooses to forget it.

import * as F from './frost.ts';
import { randomBytes, bytesToHex, refuse } from './bytes.ts';
import { compHex, commitmentHex, type Commitment } from './curve.ts';

export interface Account { C: Commitment; npub: string; a0: bigint; a1: bigint; next: number }

/** A new account from a fresh key, or from an nsec (hex) the person already has. */
export function createAccount(nsecHex?: string): Account {
  const secret = BigInt('0x' + (nsecHex ?? bytesToHex(randomBytes(32))));
  const { commitment: C, a0, a1 } = F.deal(secret);
  return { C, npub: compHex(C[0]).slice(2), a0, a1, next: 1 };
}

/** The next piece. Indices are never reused, so a blocked piece's index stays dead. */
export function issuePiece(acct: Account): { i: number; share: bigint } {
  if (acct.a0 === 0n) refuse('nsec_forgotten');
  const i = acct.next++;
  return { i, share: F.pieceAt(acct.a0, acct.a1, i) };
}

export const commitmentOf = (acct: Account) => commitmentHex(acct.C);
