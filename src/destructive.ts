// What the box asks about before it signs, and what it never signs (SPEC 11.6, "The tap"). The box is the
// authority on this (Aaron, 2026-11-20): it answers with the reason in plain words, and a device asks the person
// and sends the same request again with their answer. Devices need no copy of these rules. Marble may keep its
// own checks on top.
//
// Two levels (Aaron, 2026-11-20). Level 1, "Are you sure?": Yes or No on the device the person is using, and the
// device says Yes with `tapped: true` (the box answers `needs_tap`). Level 2, "Never by accident": erasing the
// account, wiping the profile, emptying the follow list, deleting a whole kept list, a list's private part
// emptied. Yes only on the phone, behind the fingerprint the box checks as it does for an account change (SPEC 4):
// the box answers `needs_fingerprint` (or `no_chip_key` to a device with no chip key), and `tapped` alone never
// signs one.
//
// The rules are Marble's (android/signer/.../cosign/core/Policy.kt, `refuse` and `hold`), in the words Marble
// shows the person, plus the box's own four from before: a request to vanish, five or more deletions at once,
// a follow list with no p tag, and a profile with nothing in it. Where Marble and those four differ on the same
// event, the box asks if either would. Rules that compare with the last version need `prev`, the latest version
// of that list the box signed (box/lists.ts); without one they say nothing, as on a new phone.

import type { UnsignedEvent } from './event.ts';
import { parseJson } from './bytes.ts';

/** The kinds whose last signed version is kept to compare with: Marble's kept kinds (Policy.ARCHIVED). */
export const KEPT = new Set([0, 3, 10000, 10001, 10002, 10003, 10004, 10006, 10007, 10015, 10030, 30000, 30001, 30002, 30003, 30004, 30015, 30030]);
/** How far ahead of now a clock may be; past this, an event is dated in the future. */
export const AHEAD = 600;

const NAMES: Record<number, [string, string]> = {
  0: ['profile', 'profile field'], 3: ['follow list', 'follow'], 10000: ['mute list', 'mute'], 10001: ['pinned notes', 'pin'],
  10002: ['relay list', 'relay'], 10003: ['bookmarks', 'bookmark'], 10004: ['communities', 'community'],
  10006: ['blocked relays', 'relay'], 10007: ['search relays', 'relay'], 10015: ['interests', 'interest'], 10030: ['emoji list', 'emoji'],
  30000: ['follow set', 'person'], 30001: ['list', 'item'], 30002: ['relay set', 'relay'], 30003: ['bookmark set', 'bookmark'],
  30004: ['curation set', 'item'], 30015: ['interest set', 'interest'], 30030: ['emoji set', 'emoji'],
};
const EVENT_NAMES: Record<number, string> = {
  1: 'note', 4: 'DM', 5: 'deletion', 6: 'repost', 7: 'reaction', 13: 'DM', 14: 'DM', 16: 'repost', 62: 'request to vanish',
  1111: 'comment', 9734: 'zap request', 22242: 'relay login', 24242: 'upload login', 27235: 'web login', 30023: 'article', 30078: 'app data', 10046: 'login page',
};
const RELAYISH = new Set([10002, 10006, 10007, 30002]);
const replaceable = (k: number) => k === 0 || k === 3 || (k >= 10000 && k < 20000) || (k >= 30000 && k < 40000);
/** A named set: one version per d tag. */
export const namedSet = (k: number) => k >= 30000 && k < 40000;
const kindName = (k: number) => NAMES[k]?.[0] ?? EVENT_NAMES[k] ?? `kind ${k} event`;
const itemName = (k: number) => NAMES[k]?.[1] ?? 'item';
const plural = (n: number, k: number) => `${n} ${itemName(k)}${n === 1 ? '' : 's'}`;
const upper = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
function day(t: number) { const d = new Date(t * 1000); return Number.isNaN(d.getTime()) ? 'far ahead' : d.toISOString().slice(0, 10); }

/** Replaceable lists are kept by kind; named sets by kind and d tag. */
export function keyOf(e: { kind: number; tags: string[][] }): string {
  return namedSet(e.kind) ? `${e.kind}:${e.tags.find((t) => t[0] === 'd')?.[1] ?? ''}` : `${e.kind}`;
}

// ── Profiles (kind 0) ──
// One strict reading, the same everywhere in the box: the content is exactly one JSON object as Keykin's own
// reader reads kind 0 (bytes.ts parseJson with numbers by RFC 8259's grammar): a key named twice, a control
// character in a string (other than \b \t \n \f \r), a lone surrogate, a byte order mark, loose JSON or text
// after the object make it no profile at all. No profile counts as an empty one. A field is filled when it is a
// string with at least one character that is not white space, a control character or a format character (so a
// name that is only a byte order mark or a zero-width joiner is empty). Anything that is not a string is empty.
export function profileOf(content: string): Record<string, unknown> | null {
  try {
    const p = parseJson(content, { numbers: 'grammar' });
    return p && typeof p === 'object' && !Array.isArray(p) ? p : null;
  } catch { return null; }
}
const filled = (v: unknown) => typeof v === 'string' && /[^\s\p{Cc}\p{Cf}]/u.test(v);
/** The fields compared with the last version (Marble's eight), and those of which one must be filled (the box's six). */
const PROFILE_FIELDS = ['name', 'display_name', 'picture', 'about', 'nip05', 'lud16', 'banner', 'website'];
const ANY_OF = ['name', 'display_name', 'about', 'picture', 'nip05', 'lud16'];

/** Each entry of a list (who, which relay, which note), as Marble counts them. */
function items(e: UnsignedEvent): string[] {
  if (e.kind === 3) return e.tags.filter((t) => t.length > 1 && t[0] === 'p').map((t) => t[1]);
  if (RELAYISH.has(e.kind)) return e.tags.filter((t) => t.length > 1 && (t[0] === 'r' || t[0] === 'relay')).map((t) => t[1].replace(/\/+$/, ''));
  return e.tags.filter((t) => t.length && t[0] !== 'd' && t[0] !== 'title' && t[0] !== 'description').map((t) => JSON.stringify(t.slice(0, 2)));
}
/** The private part (encrypted, in the content) was there and is gone. An old follow list's relays in plain JSON are no private part. */
const blank = (s: string) => !s.trim();
const emptied = (prev: UnsignedEvent, now: UnsignedEvent) => now.kind !== 0 && !blank(prev.content) && !prev.content.trimStart().startsWith('{') && blank(now.content);
const asInt = (s: string) => (/^[+-]?[0-9]+$/.test(s) ? Number(s) : NaN);

/** Set when this must never be signed, a Yes or not: a list or an address deletion dated ahead. */
export function refusal(e: UnsignedEvent, now: number): string | null {
  if (e.created_at <= now + AHEAD) return null;
  if (replaceable(e.kind)) return `${upper(kindName(e.kind))} dated ${day(e.created_at)}: a version dated ahead would block every later change`;
  if (e.kind === 5 && e.tags.some((t) => t.length && t[0] === 'a')) return `Deletion dated ${day(e.created_at)}: it would delete every version until then`;
  return null;
}

/** How hard to undo: 1 asks "Are you sure?", 2 is never done by accident (only on the phone, behind the fingerprint). */
export type Level = 1 | 2;
/** A question for the person: what would be lost, in plain words, and its level. */
export interface Question { says: string; level: Level }
const q = (says: string, level: Level): Question => ({ says, level });

/** Set when the person has to say Yes first: what would be lost, in plain words, and how. `prev` is the last version the box signed. */
export function question(e: UnsignedEvent, prev: UnsignedEvent | null, now: number): Question | null {
  if (e.created_at > now + AHEAD) {
    if (refusal(e, now)) return null;
    // Dated ahead is level 1, unless the same event dated now would be level 2 (a request to vanish, a list's deletion by k).
    return q(`${upper(kindName(e.kind))} dated in the future (${day(e.created_at)})`, question({ ...e, created_at: now }, prev, now)?.level ?? 1);
  }
  if (e.kind === 62) return q('Ask relays to erase everything you have ever published', 2);
  if (e.kind === 5) {
    const targets = e.tags.filter((t) => t.length && (t[0] === 'e' || t[0] === 'a')).length;
    const lists = e.tags.filter((t) => t.length > 1 && (t[0] === 'a' || t[0] === 'k')).map((t) => asInt(t[1].split(':')[0])).filter((k) => KEPT.has(k));
    if (lists.length) return q(`Delete your ${kindName(lists[0])}`, 2);
    return targets >= 5 ? q(`Delete ${targets} of your events`, 1) : null;
  }
  if (e.kind === 0) {
    const after = profileOf(e.content) ?? {}, was = (prev && profileOf(prev.content)) ?? {};
    const gone = PROFILE_FIELDS.filter((k) => filled(was[k]) && !filled(after[k]));
    // Nothing left that says who this is: the whole profile goes. Fields lost with some still there: level 1.
    const wiped = !ANY_OF.some((k) => filled(after[k]));
    return gone.length >= 2 || wiped ? q(`Wipe your profile: ${gone.join(', ') || 'everything'}`, wiped ? 2 : 1) : null;
  }
  const noOne = e.kind === 3 && !e.tags.some((t) => t[0] === 'p') ? q('Empty your follow list', 2) : null;
  if (!KEPT.has(e.kind) || !prev) return noOne;
  // The encrypted private part (private bookmarks, private mutes): an app that cannot read it may write the list back without it.
  if (emptied(prev, e)) return q(`Empty your private ${kindName(e.kind)}`, 2);
  const before = items(prev), after = items(e), kept = new Set(after), had = new Set(before);
  const removed = before.filter((x) => !kept.has(x)).length, added = after.filter((x) => !had.has(x)).length;
  // Of the lists emptied, only the follow list is level 2.
  if (!after.length && before.length >= 3) return q(`Empty your ${kindName(e.kind)} (it has ${plural(before.length, e.kind)})`, e.kind === 3 ? 2 : 1);
  const big = RELAYISH.has(e.kind) ? removed >= 2 && removed >= before.length * 0.5 : removed >= 10 && removed >= before.length * 0.2;
  if (big) return q(`Remove ${removed} of your ${before.length} ${itemName(e.kind)}s` + (added > 0 ? ` (and add ${added})` : ''), 1);
  return noOne;
}

/** The question's words alone, as before levels. */
export function hold(e: UnsignedEvent, prev: UnsignedEvent | null, now: number): string | null { return question(e, prev, now)?.says ?? null; }

/**
 * The box's answer for an event: sign it, ask first (`says` is the question, `level` how), or refuse it (`says` is
 * why). `level` is null unless it asks.
 */
export function judge(e: UnsignedEvent, prev: UnsignedEvent | null, now: number): { decision: 'sign' | 'ask' | 'refuse'; says: string | null; level: Level | null } {
  const no = refusal(e, now);
  if (no) return { decision: 'refuse', says: no, level: null };
  const ask = question(e, prev, now);
  return ask ? { decision: 'ask', says: ask.says, level: ask.level } : { decision: 'sign', says: null, level: null };
}

/** What a device that is not the phone says for a level 2 event it was not let sign. */
export const FROM_PHONE = 'Do this from your phone.';
export const onlyFromPhone = (why: string) => `${why.replace(/[.\s]+$/, '')}. ${FROM_PHONE}`;
