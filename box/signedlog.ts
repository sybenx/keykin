// The signature log (SPEC 11.6, Recent signing): which two pieces made each signature or message key. It lives
// beside state.json, never in it, one file per account, `<dir>/<account hex>/signed.json`: the box rewrites the
// whole state file on every change, and a month of signing is too big to rewrite that often. In memory between
// writes; written with the state, so at most about once a minute while signing.

import { MemoryShelf, type Shelf } from './lists.ts';

/**
 * One signature or message key two pieces made. `asker` and `helper` are member keys: the piece that started
 * it and the one that answered. For a row the box writes as helper, `signedAt` and `receivedAt` are the same.
 * A row a helping device reports later (SPEC 11.7) has `receivedAt` when the box got it. `kind` and `eventId`
 * are for `sign` only; `grant` when the request named one.
 */
export interface SignedRow { signedAt: number; receivedAt: number; asker: string; helper: string; op: 'sign' | 'ecdh'; kind?: number; eventId?: string; grant?: string }

/** How long rows are kept: the window the relay alarm looks back over (SPEC 11.7). */
export const SIGNED_DAYS = 30;
/** At most this many rows per account, whatever their age; past it the oldest goes. A busy account's month. */
export const MAX_SIGNED = 10000;
/** Message keys for the same asker, helper and grant this close together keep one row, the latest. */
export const ECDH_SAME = 600;
const FILE = 'signed.json';

export class SignedLog {
  readonly shelf: Shelf;
  #rows = new Map<string, SignedRow[]>();
  #dirty = new Set<string>();
  constructor(shelf: Shelf = new MemoryShelf()) { this.shelf = shelf; }

  /** An account's rows, oldest `signedAt` first. The array is the log's own: do not change it. */
  rows(account: string): SignedRow[] {
    let r = this.#rows.get(account);
    if (!r) {
      try { const f = JSON.parse(this.shelf.read(account, FILE) ?? ''); r = Array.isArray(f?.rows) ? f.rows : []; } catch { r = []; }
      this.#rows.set(account, r!);
    }
    return r!;
  }

  /**
   * Adds a row at its place by `signedAt`. A message key close after one for the same asker, helper and grant
   * replaces that row: reading a conversation asks for many, and they would push every signature out. Rows older
   * than SIGNED_DAYS go, and past MAX_SIGNED the oldest. Nothing is written until [flush].
   */
  add(account: string, row: SignedRow, now: number) {
    const log = this.rows(account);
    if (row.op === 'ecdh') {
      let k = log.length - 1;
      while (k >= 0 && !(log[k].op === 'ecdh' && log[k].asker === row.asker && log[k].helper === row.helper && log[k].grant === row.grant)) k--;
      if (k >= 0 && row.signedAt - log[k].signedAt < ECDH_SAME && row.signedAt >= log[k].signedAt) log.splice(k, 1);
    }
    let at = log.length;
    while (at > 0 && log[at - 1].signedAt > row.signedAt) at--;
    log.splice(at, 0, row);
    const cut = now - SIGNED_DAYS * 86400;
    let old = 0;
    while (old < log.length && log[old].signedAt < cut) old++;
    log.splice(0, Math.max(old, log.length - MAX_SIGNED));
    this.#dirty.add(account);
  }

  /** Writes every account whose rows changed since the last flush. A full disk never fails a signature. */
  flush() {
    for (const a of this.#dirty) { try { this.shelf.write(a, FILE, JSON.stringify({ rows: this.#rows.get(a) ?? [] })); this.#dirty.delete(a); } catch { /* next time */ } }
  }
  /** Forgets an account's log (it was removed from the box). */
  forget(account: string) { this.#rows.delete(account); this.#dirty.delete(account); this.shelf.drop(account); }
  /** Forgets the logs of every account the box no longer holds. */
  tidy(held: (account: string) => boolean) { for (const a of this.shelf.accounts()) if (!held(a)) this.forget(a); }
}
