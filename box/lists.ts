// The list store (SPEC 6, "The list store"): the latest version the box signed of each kept list (src/destructive.ts
// KEPT), so the box can judge a change against it the way Marble does on the phone. It lives beside state.json,
// never in it: one small file per account per list, written atomically and only when that list changes.
//
//   <dir>/<account hex>/<kind>.json              a replaceable list (profile, follows, relays, bookmarks, ...)
//   <dir>/<account hex>/<kind>-<sha256(d)>.json  a named set, one per d tag (the first 32 hex digits of SHA-256 of the d tag)
//   <dir>/<account hex>/sets.json                 when each named set last changed, and the sets no longer compared
//
// A list file is `{ "key": "30003:reading", "at": <unix seconds the box kept it>, "event": { id, pubkey, created_at,
// kind, tags, content } }`. The box never has the finished signature, only the event it helped sign.
//
// Named sets are soft-capped per account (`cap`, the admin's setting): past it the least recently changed set is
// dropped and listed in sets.json under `uncompared`, and the box says so in the account's activity. Over the cap
// never refuses a signature: that set is simply not compared until it changes again. Replaceable lists are a
// fixed handful of kinds and have no cap. A list stays until its account is removed.

import { mkdirSync, readFileSync, writeFileSync, renameSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { shaHex } from '../src/bytes.ts';
import { keyOf, namedSet } from '../src/destructive.ts';
import type { UnsignedEvent } from '../src/event.ts';

/** The proposed default for how many named sets a box keeps per account. The admin can change it. */
export const KEPT_SETS = 200;
/** How many dropped sets `uncompared` remembers per account, newest kept. */
const UNCOMPARED_MOST = 50;

export type KeptEvent = UnsignedEvent & { id: string };
export interface Uncompared { key: string; at: number }
interface Sets { sets: Record<string, { key: string; at: number }>; uncompared: Uncompared[] }

/** Where the files go. On disk for a running box; in memory for tests and a box with no directory. */
export interface Shelf {
  read(account: string, name: string): string | null;
  /** Atomically: whoever reads sees the old text or the new, never part of one. */
  write(account: string, name: string, text: string): void;
  remove(account: string, name: string): void;
  /** Forget everything of one account. */
  drop(account: string): void;
  accounts(): string[];
}

export class MemoryShelf implements Shelf {
  #m = new Map<string, Map<string, string>>();
  /** How many writes, for tests: a write happens only when a list changes. */
  writes = 0;
  read(a: string, n: string) { return this.#m.get(a)?.get(n) ?? null; }
  write(a: string, n: string, t: string) { this.writes++; (this.#m.get(a) ?? this.#m.set(a, new Map()).get(a)!).set(n, t); }
  remove(a: string, n: string) { this.#m.get(a)?.delete(n); }
  drop(a: string) { this.#m.delete(a); }
  accounts() { return [...this.#m.keys()]; }
  names(a: string) { return [...(this.#m.get(a)?.keys() ?? [])]; }
}

const ACCOUNT = /^[0-9a-f]{64}$/, NAME = /^[0-9]{1,5}(-[0-9a-f]{32})?\.json$|^sets\.json$|^signed\.json$/;   // signed.json: box/signedlog.ts
export class DiskShelf implements Shelf {
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; mkdirSync(dir, { recursive: true, mode: 0o700 }); }
  #path(a: string, n: string) {
    if (!ACCOUNT.test(a) || !NAME.test(n)) throw new Error(`list store: bad name ${a}/${n}`);
    return join(this.dir, a, n);
  }
  read(a: string, n: string) { try { return readFileSync(this.#path(a, n), 'utf8'); } catch { return null; } }
  write(a: string, n: string, t: string) {
    const p = this.#path(a, n);
    mkdirSync(join(this.dir, a), { recursive: true, mode: 0o700 });
    writeFileSync(p + '.tmp', t, { mode: 0o600 });
    renameSync(p + '.tmp', p);
  }
  remove(a: string, n: string) { rmSync(this.#path(a, n), { force: true }); }
  drop(a: string) { if (ACCOUNT.test(a)) rmSync(join(this.dir, a), { recursive: true, force: true }); }
  accounts() { return existsSync(this.dir) ? readdirSync(this.dir).filter((x) => ACCOUNT.test(x)) : []; }
}

const fileOf = (e: { kind: number; tags: string[][] }) => namedSet(e.kind) ? `${e.kind}-${shaHex(e.tags.find((t) => t[0] === 'd')?.[1] ?? '').slice(0, 32)}.json` : `${e.kind}.json`;

export class Lists {
  readonly shelf: Shelf;
  constructor(shelf: Shelf = new MemoryShelf()) { this.shelf = shelf; }

  /** The latest version kept of the list `e` would replace, or null when there is none. */
  latest(account: string, e: { kind: number; tags: string[][] }): KeptEvent | null {
    const text = this.shelf.read(account, fileOf(e));
    if (!text) return null;
    try {
      const f = JSON.parse(text);
      // A file whose key does not match (two d tags with the same short hash) is no earlier version of this one.
      return f?.key === keyOf(e) && f.event && typeof f.event === 'object' ? f.event : null;
    } catch { return null; }
  }

  /**
   * Keeps `e` if it is newer than what is kept (an equal date replaces, the same id does nothing). For a named set,
   * past `cap` the least recently changed sets go. Returns whether anything was written, and the keys of the sets
   * that went, so the box can say so.
   */
  keep(account: string, e: KeptEvent, cap: number, now: number): { kept: boolean; dropped: string[] } {
    const have = this.latest(account, e);
    if (have && (have.created_at > e.created_at || have.id === e.id)) return { kept: false, dropped: [] };
    const name = fileOf(e), key = keyOf(e), dropped: string[] = [];
    if (!namedSet(e.kind)) { this.#put(account, name, key, e, now); return { kept: true, dropped }; }
    const s = this.#sets(account);
    s.sets[name] = { key, at: now };
    s.uncompared = s.uncompared.filter((u) => u.key !== key);
    const all = Object.entries(s.sets).sort((x, y) => y[1].at - x[1].at || (x[0] === name ? -1 : y[0] === name ? 1 : 0));
    for (const [n, v] of all.slice(Math.max(0, cap))) {
      delete s.sets[n]; this.shelf.remove(account, n);
      if (n !== name || have) dropped.push(v.key);     // a set never kept (a cap of 0) is not news
      s.uncompared.push({ key: v.key, at: now });
    }
    if (s.uncompared.length > UNCOMPARED_MOST) s.uncompared.splice(0, s.uncompared.length - UNCOMPARED_MOST);
    if (s.sets[name]) this.#put(account, name, key, e, now);
    this.shelf.write(account, 'sets.json', JSON.stringify(s));
    return { kept: !!s.sets[name], dropped };
  }

  /** The named sets dropped past the cap, newest last: they are not compared until they change again. */
  uncompared(account: string): Uncompared[] { return this.#sets(account).uncompared; }
  /** How many named sets are kept for an account now. */
  setCount(account: string) { return Object.keys(this.#sets(account).sets).length; }
  /** Forgets every list of an account (it was removed from the box). */
  forget(account: string) { this.shelf.drop(account); }
  /** Forgets the lists of every account the box no longer holds. */
  tidy(held: (account: string) => boolean) { for (const a of this.shelf.accounts()) if (!held(a)) this.shelf.drop(a); }

  #put(account: string, name: string, key: string, e: KeptEvent, now: number) {
    const event = { id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content };
    this.shelf.write(account, name, JSON.stringify({ key, at: now, event }));
  }
  #sets(account: string): Sets {
    try {
      const s = JSON.parse(this.shelf.read(account, 'sets.json') ?? '');
      if (s && typeof s.sets === 'object' && Array.isArray(s.uncompared)) return s;
    } catch { /* none yet */ }
    return { sets: {}, uncompared: [] };
  }
}
