// One signing round between two pieces. The asker (always a device) sends its commitment; the
// helper (the box, or another device) answers with its own commitment and its partial signature in
// the same reply, so a signature costs one round trip. `msg` is the 32-byte Nostr event id, hex.

import * as F from './frost.ts';
import { sha, refuse } from './bytes.ts';
import type { Commitment } from './curve.ts';

export interface Piece { C: Commitment; i: number; share: bigint }
export interface Answer { commit: F.SignCommit; z: string }

const fresh = (p: Piece, msg: string) => F.commit(p.C, p.i, p.share, F.hedge(p.share, sha('keykin2-round', msg)));

/** Asker, step 1: fresh nonces and the commitment to send. */
export function ask(p: Piece, msg: string) { return fresh(p, msg); }

/** Helper: answer an asker's commitment. Nonces are made here and used once, here. */
export function answer(p: Piece, msg: string, asker: F.SignCommit): Answer {
  if (asker.i === p.i) refuse('same_piece');
  const mine = fresh(p, msg);
  const commits = [asker, mine.commit];
  return { commit: mine.commit, z: F.signShare(p.C, p.i, p.share, mine.nonces, msg, commits) };
}

/** Asker, step 2: check the helper's partial, add its own, and return the BIP-340 signature. */
export function finish(p: Piece, msg: string, mine: { nonces: F.Nonces; commit: F.SignCommit }, a: Answer): string {
  if (a.commit.i === p.i) refuse('same_piece');
  const commits = [mine.commit, a.commit];
  if (!F.verifyShare(p.C, msg, commits, a.commit.i, a.z)) refuse('bad_partial');
  const z = F.signShare(p.C, p.i, p.share, mine.nonces, msg, commits);
  return F.aggregate(p.C, msg, commits, [{ i: p.i, z }, { i: a.commit.i, z: a.z }]);
}
