#!/usr/bin/env node
// Writes vectors/hard-to-undo.json: shared cases for "is this event hard to undo?", the question a signer asks
// before it signs. The box is the authority on it (Aaron, 2026-11-20). Two implementations answer it:
//
//   box     The Keykin box: box/box.ts #sign with src/destructive.ts judge(event, prev, now). It refuses an event
//           dated ahead with `dated_ahead`, one it asks about at level 1 with `needs_tap` unless the request says
//           the person tapped Yes (`tapped: true`), and one at level 2 with `needs_fingerprint` unless the request
//           carries the asking device's fingerprint (`fp`, as for an account change); `tapped` alone never signs
//           that. All carry the words as `why`. `prev` is the last version
//           of that list the box signed, from its list store (box/lists.ts).
//   marble  Marble's own rules, android/signer/src/main/java/cc/aaro/cosign/core/Policy.kt (refuse and hold), which
//           Marble keeps on top: they judge a list or profile against the last version the phone saw (`prev`).
//
// Until 2026-11-20 the box had four rules of its own (keykin 0.1.23 and before) and Marble carried a copy of them
// (Device.destructive). The box now has Marble's rules too, in Marble's words, and asks where either would.
//
//   node tools/hard-to-undo-vectors.mjs                  writes vectors/hard-to-undo.json
//   node tools/hard-to-undo-vectors.mjs --copy <dir>     also copies it to <dir>, with hard-to-undo.SOURCE (the Keykin
//                                                        commit and the file's sha256), for a repo that must not
//                                                        reach outside itself at build time (Marble's test resources)
//   node tools/hard-to-undo-vectors.mjs --check <dir>    exits 1 if the copy in <dir> was edited or is not this one
//
// `answers` is what each implementation answers today: `decision` is sign, ask or refuse, `says` the words it gives
// (null when it signs), `level` how it asks (1: "Are you sure?", Yes or No on the device in use; 2: "Never by
// accident", Yes only on the phone behind the fingerprint; null when it does not ask). `expect` is the box's decision: the box is where disputes are decided. `outcome` is what
// that means on each kind of device (see `outcomes`). `uncaught` marks a case nobody has decided to catch yet.
// test/hard-to-undo-vectors.test.ts holds src/destructive.ts and the box to the box answers; Marble's
// HardToUndoVectorsTest holds Policy.kt to its own.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const NOW = 1_800_000_000;          // 2027-01-15T08:00:00Z
const Y2099 = 4_070_908_800;        // 2099-01-01
const ME = 'f'.repeat(63) + '1';
const pk = (i) => i.toString(16).padStart(64, '0');
const ev = (kind, tags = [], content = '', created_at = NOW) => ({ pubkey: ME, created_at, kind, tags, content });
const ps = (n, from = 1) => Array.from({ length: n }, (_, i) => ['p', pk(from + i)]);
const es = (n, from = 1) => Array.from({ length: n }, (_, i) => ['e', pk(from + i)]);
const rs = (...urls) => urls.map((u) => ['r', u]);
const json = (o) => JSON.stringify(o);
const SEALED = 'AhjhT8nNyAh4ozUgSqzQxVUHvOJ9n2CXhqC2HoU5Do2pW2oFmV1E8vL+Rq1PKbmT9wWkV8l7QhJbH0mF2g6uVxk=';   // looks like NIP-44, is not
const NIP04 = 'o6Lq2T5xvRk3o8QKk3g6WQ==?iv=Zm9vYmFyYmF6cXV4MTIzNA==';

// ── What each one answers ──
// `level` is how the person is asked (Aaron, 2026-11-20): 1, "Are you sure?" (Yes or No on the device in use), or
// 2, "Never by accident" (Yes only on the phone, behind the fingerprint the box checks). Null when nobody is asked.
const sign = { decision: 'sign', says: null, level: null };
const ask = (says) => ({ decision: 'ask', says, level: 1 });
const never = (says) => ({ decision: 'ask', says, level: 2 });
const refuse = (says) => ({ decision: 'refuse', says, level: null });
const VANISH = never('Ask relays to erase everything you have ever published');
const DEL5 = ask('Delete 5 of your events');
const FOLLOWS = never('Empty your follow list');
const PROFILE = never('Wipe your profile: everything');
const M = 'marble', B = 'box';

// ── Every rule each one has ──
const rules = [
  { id: 'marble-ahead-list', impl: [M, B], kinds: '0, 3, 10000-19999, 30000-39999', then: 'refuse',
    when: 'created_at more than 600 s after now', says: '"<Kind> dated <day>: a version dated ahead would block every later change"' },
  { id: 'marble-ahead-delete-a', impl: [M, B], kinds: '5', then: 'refuse',
    when: 'created_at more than 600 s after now, and any a tag', says: '"Deletion dated <day>: it would delete every version until then"' },
  { id: 'marble-ahead', impl: [M, B], kinds: 'any other', then: 'ask', level: '1, or 2 when the same event dated now would be level 2',
    when: 'created_at more than 600 s after now', says: '"<Kind> dated in the future (<day>)"' },
  { id: 'marble-vanish', impl: [M, B], kinds: '62', then: 'ask', level: 2, when: 'always', says: '"Ask relays to erase everything you have ever published"' },
  { id: 'marble-delete-list', impl: [M, B], kinds: '5', then: 'ask', level: 2,
    when: 'an a tag (kind:pubkey:d) or k tag naming a kind Marble keeps (0, 3, 10000-10004, 10006, 10007, 10015, 10030, 30000-30004, 30015, 30030)',
    says: '"Delete your <name of the first such kind>"' },
  { id: 'marble-delete-5', impl: [M, B], kinds: '5', then: 'ask', level: 1, when: '5 or more e and a tags (after marble-delete-list)', says: '"Delete <n> of your events"' },
  { id: 'marble-profile-wipe', impl: [M, B], kinds: '0', then: 'ask', level: '2 when none of name, display_name, about, picture, nip05, lud16 is filled after (the whole profile goes); else 1',
    when: 'with a previous version: 2 or more of name, display_name, picture, about, nip05, lud16, banner, website go from filled to empty, or the new content is no JSON object (or an empty one) and the old one had keys. '
      + 'The box reads both with its one strict reading (see box-profile-empty), so a field is filled only when it is a string with something in it',
    says: '"Wipe your profile: <fields>" ("everything" when none of the eight were filled)' },
  { id: 'marble-private-emptied', impl: [M, B], kinds: 'the kept kinds except 0', then: 'ask', level: 2,
    when: 'with a previous version whose content was not blank and did not start with "{" (a private part), the new content is blank',
    says: '"Empty your private <name>"' },
  { id: 'marble-list-emptied', impl: [M, B], kinds: 'the kept kinds except 0', then: 'ask', level: '2 for the follow list (kind 3), 1 for the rest',
    when: 'with a previous version of 3 or more entries, none left (kind 3 counts p tags with a value; relay kinds r and relay tags; the rest every tag but d, title, description)',
    says: '"Empty your <name> (it has <n> <items>)"' },
  { id: 'marble-relays-most', impl: [M, B], kinds: '10002, 10006, 10007, 30002', then: 'ask', level: 1,
    when: 'with a previous version: 2 or more relays removed, and at least half (a trailing / does not count)',
    says: '"Remove <r> of your <n> relays" (+ " (and add <a>)")' },
  { id: 'marble-list-most', impl: [M, B], kinds: 'the other kept kinds except 0', then: 'ask', level: 1,
    when: 'with a previous version: 10 or more entries removed, and at least a fifth', says: '"Remove <r> of your <n> <items>s" (+ " (and add <a>)")' },
  { id: 'box-vanish', impl: [B], kinds: '62', then: 'ask', level: 2, when: 'always (the same as marble-vanish)', says: '"Ask relays to erase everything you have ever published"' },
  { id: 'box-delete-5', impl: [B], kinds: '5', then: 'ask', level: 1, when: '5 or more e and a tags (the same as marble-delete-5)', says: '"Delete <n> of your events"' },
  { id: 'box-follows-empty', impl: [B], kinds: '3', then: 'ask', level: 2, when: 'no tag named p, whatever came before (after the marble rules)', says: '"Empty your follow list"' },
  { id: 'box-profile-empty', impl: [B], kinds: '0', then: 'ask', level: 2,
    when: 'none of name, display_name, about, picture, nip05, lud16 is filled, whatever came before. One strict reading: the content is exactly one JSON object as Keykin reads kind 0 '
      + '(src/bytes.ts parseJson, numbers by grammar); a key named twice, a control character in a string, a lone surrogate, a byte order mark, loose JSON or text after it make it no profile, '
      + 'which counts as empty. A field is filled when it is a string with a character that is not white space, a control character or a format character',
    says: '"Wipe your profile: <fields that were filled before>" ("everything" when none were, or there is no earlier version)' },
];

// ── The cases ──
const cases = [];
/**
 * `b`, the box, defaults to Marble's answer where Marble does not sign: the box has Marble's rules, in Marble's words.
 * Give it where Marble signs and the box does not (its own four rules, and its strict reading of a profile).
 */
function c({ why, rules: r, e, prev = null, m, b = m, uncaught }) {
  const answers = { [M]: m, [B]: b };
  if (m.decision !== 'sign' && (b.decision !== m.decision || b.says !== m.says || b.level !== m.level)) throw new Error(`${why}: the box answers as Marble does where Marble does not sign`);
  cases.push({ why, rules: r, event: e, prev, answers, expect: b.decision, level: b.level, outcome: outcome(answers), ...(uncaught ? { uncaught } : {}) });
}
/** What a person sees on each kind of device (see `outcomes`). */
function outcome(a) {
  const no = a[M].decision === 'refuse' || a[B].decision === 'refuse';
  const level = Math.max(a[M].level ?? 0, a[B].level ?? 0);
  const box = a[B].decision === 'refuse' ? 'dated_ahead' : a[B].level === 2 ? 'needs_fingerprint' : a[B].level === 1 ? 'needs_tap' : 'signs';
  const alone = a[M].decision === 'refuse' ? 'refuses' : a[M].level === 2 ? 'fingerprint' : a[M].level === 1 ? 'asks' : 'signs';
  return {
    marble: no ? 'refuses' : level === 2 ? 'fingerprint' : level === 1 ? 'asks' : 'signs',
    marbleAlone: alone,
    mac: { dated_ahead: 'refuses', needs_fingerprint: 'phone', needs_tap: 'asks', signs: 'signs' }[box],
    keykinDevices: box,
  };
}

// Plain things
c({ why: 'a note', rules: [], e: ev(1, [], 'gm'), m: sign });
c({ why: 'a reaction', rules: [], e: ev(7, [['e', pk(1)], ['p', pk(2)]], '+'), m: sign });

// Request to vanish
c({ why: 'vanish from every relay', rules: ['marble-vanish', 'box-vanish'], e: ev(62, [['relay', 'ALL_RELAYS']]), m: never('Ask relays to erase everything you have ever published') });
c({ why: 'vanish from one relay: still the whole account there', rules: ['marble-vanish', 'box-vanish'], e: ev(62, [['relay', 'wss://r.example']]), m: never('Ask relays to erase everything you have ever published') });

// Deletions
c({ why: 'delete 4 posts', rules: ['marble-delete-5', 'box-delete-5'], e: ev(5, es(4)), m: sign });
c({ why: 'delete 5 posts', rules: ['marble-delete-5', 'box-delete-5'], e: ev(5, es(5)), m: ask('Delete 5 of your events') });
c({ why: 'delete 5 articles by address (kind 30023 is not a kept kind)', rules: ['marble-delete-5', 'box-delete-5'],
  e: ev(5, Array.from({ length: 5 }, (_, i) => ['a', `30023:${ME}:post-${i}`])), m: ask('Delete 5 of your events') });
c({ why: 'delete 3 posts and 2 articles: e and a count together', rules: ['marble-delete-5', 'box-delete-5'],
  e: ev(5, [...es(3), ['a', `30023:${ME}:a`], ['a', `30023:${ME}:b`]]), m: ask('Delete 5 of your events') });
c({ why: 'delete 4 posts with a k tag: k is not a target', rules: ['marble-delete-5', 'box-delete-5'], e: ev(5, [...es(4), ['k', '1']]), m: sign });
c({ why: 'delete the follow list by address', rules: ['marble-delete-list'], e: ev(5, [['a', `3:${ME}:`]]), m: never('Delete your follow list') });
c({ why: 'delete one event, saying it is a relay list (k 10002)', rules: ['marble-delete-list'], e: ev(5, [['e', pk(1)], ['k', '10002']]), m: never('Delete your relay list') });
c({ why: 'delete the bookmarks by k 10003', rules: ['marble-delete-list'], e: ev(5, [['e', pk(1)], ['k', '10003']]), m: never('Delete your bookmarks') });
c({ why: 'delete a bookmark set by address', rules: ['marble-delete-list'], e: ev(5, [['a', `30003:${ME}:reading`]]), m: never('Delete your bookmark set') });
c({ why: 'delete 5, one of them the follow list: Marble names the list', rules: ['marble-delete-list', 'box-delete-5'],
  e: ev(5, [['a', `3:${ME}:`], ...es(4)]), m: never('Delete your follow list') });
c({ why: 'delete one article by address: every version of it, and neither asks', rules: [], e: ev(5, [['a', `30023:${ME}:my-essay`]]), m: sign,
  uncaught: 'An address deletion removes every version of an article up to now, and only refusing it when dated ahead covers that. Is one article worth a question?' });

// Follow list (kind 3)
c({ why: 'the first follow list this phone sees', rules: [], e: ev(3, ps(30)), m: sign });
c({ why: 'follow one more', rules: [], e: ev(3, ps(31)), prev: ev(3, ps(30)), m: sign });
c({ why: 'unfollow 9 of 30: under 10', rules: ['marble-list-most'], e: ev(3, ps(21)), prev: ev(3, ps(30)), m: sign,
  uncaught: 'Under 10 removed is never asked about, even 9 of 30 (30 percent).' });
c({ why: 'unfollow 10 of 30', rules: ['marble-list-most'], e: ev(3, ps(20)), prev: ev(3, ps(30)), m: ask('Remove 10 of your 30 follows') });
c({ why: 'unfollow 10 of 50: exactly a fifth', rules: ['marble-list-most'], e: ev(3, ps(40)), prev: ev(3, ps(50)), m: ask('Remove 10 of your 50 follows') });
c({ why: 'unfollow 10 of 51: under a fifth', rules: ['marble-list-most'], e: ev(3, ps(41)), prev: ev(3, ps(51)), m: sign });
c({ why: 'all 30 replaced by 30 others', rules: ['marble-list-most'], e: ev(3, ps(30, 101)), prev: ev(3, ps(30)), m: ask('Remove 30 of your 30 follows (and add 30)') });
c({ why: 'down to 1 of 200', rules: ['marble-list-most', 'box-follows-empty'], e: ev(3, ps(1)), prev: ev(3, ps(200)), m: ask('Remove 199 of your 200 follows') });
c({ why: 'emptied from 3', rules: ['marble-list-emptied', 'box-follows-empty'], e: ev(3, []), prev: ev(3, ps(3)), m: never('Empty your follow list (it has 3 follows)') });
c({ why: 'emptied from 2', rules: ['marble-list-emptied', 'box-follows-empty'], e: ev(3, []), prev: ev(3, ps(2)), m: sign, b: FOLLOWS });
c({ why: 'emptied, with no earlier version seen (or as a site\'s own key, which Marble never compares)', rules: ['box-follows-empty'], e: ev(3, []), m: sign, b: FOLLOWS });
c({ why: 'emptied of people, hashtags kept', rules: ['marble-list-emptied', 'box-follows-empty'], e: ev(3, [['t', 'nostr']]), prev: ev(3, [...ps(3), ['t', 'nostr']]), m: never('Empty your follow list (it has 3 follows)') });
c({ why: 'only bare p tags left (no key in them): Keykin sees a p tag, Marble sees no one', rules: ['marble-list-emptied', 'box-follows-empty'],
  e: ev(3, [['p'], ['p']]), prev: ev(3, ps(3)), m: never('Empty your follow list (it has 3 follows)') });
c({ why: 'the old relay list in the content dropped, follows kept: no private part', rules: ['marble-private-emptied'],
  e: ev(3, ps(30)), prev: ev(3, ps(30), json({ 'wss://a.example': { read: true, write: true } })), m: sign });

// Profile (kind 0)
const PROF = json({ name: 'Aaron', about: 'hi', picture: 'https://x.example/p.png' });
c({ why: 'name changed', rules: [], e: ev(0, [], json({ name: 'B', about: 'x' })), prev: ev(0, [], json({ name: 'A', about: 'x' })), m: sign });
c({ why: 'the first profile', rules: [], e: ev(0, [], json({ name: 'Aaron' })), m: sign });
c({ why: 'an empty first profile', rules: ['box-profile-empty'], e: ev(0, [], '{}'), m: sign, b: PROFILE });
c({ why: 'emptied, from a name', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], '{}'), prev: ev(0, [], json({ name: 'Aaron' })), m: never('Wipe your profile: name') });
c({ why: 'one field removed', rules: ['marble-profile-wipe'], e: ev(0, [], json({ name: 'Aaron', about: 'hi' })), prev: ev(0, [], PROF), m: sign });
c({ why: 'two fields removed, the name kept', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], json({ name: 'Aaron' })), prev: ev(0, [], PROF), m: ask('Wipe your profile: picture, about') });
c({ why: 'banner and website removed, the name kept', rules: ['marble-profile-wipe'], e: ev(0, [], json({ name: 'Aaron' })), prev: ev(0, [], json({ name: 'Aaron', banner: 'https://x.example/b.png', website: 'https://x.example' })),
  m: ask('Wipe your profile: banner, website') });
c({ why: 'only a banner left: Keykin does not count banner or website', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], json({ banner: 'https://x.example/b.png' })), prev: ev(0, [], json({ name: 'Aaron', about: 'hi' })),
  m: never('Wipe your profile: name, about') });
c({ why: 'a first profile with only a website', rules: ['box-profile-empty'], e: ev(0, [], json({ website: 'https://x.example' })), m: sign, b: PROFILE });
c({ why: 'a first profile whose name is white space', rules: ['box-profile-empty'], e: ev(0, [], json({ name: '  ' })), m: sign, b: PROFILE });
c({ why: 'content that is not JSON', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], 'hello'), prev: ev(0, [], json({ name: 'Aaron' })), m: never('Wipe your profile: name') });
c({ why: 'content that is a JSON array', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], '[]'), prev: ev(0, [], json({ name: 'Aaron' })), m: never('Wipe your profile: name') });
c({ why: 'a first profile that is JSON null', rules: ['box-profile-empty'], e: ev(0, [], 'null'), m: sign, b: PROFILE });
c({ why: 'the name a number: Marble counts it as filled, Keykin wants a string', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], '{"name":5}'), prev: ev(0, [], json({ name: 'Aaron' })), m: sign, b: never('Wipe your profile: name') });
c({ why: 'loose JSON (unquoted key, single quotes): only JSON.parse refuses it', rules: ['box-profile-empty'], e: ev(0, [], "{name:'Aaron'}"), prev: ev(0, [], json({ name: 'Aaron' })), m: sign, b: never('Wipe your profile: name') });
c({ why: 'a key twice: JSON.parse keeps the last; org.json and the box\'s strict reading refuse the whole thing', rules: ['marble-profile-wipe', 'box-profile-empty'], e: ev(0, [], '{"name":"","name":"Aaron"}'), prev: ev(0, [], json({ name: 'Aaron' })),
  m: never('Wipe your profile: name') });
c({ why: 'something after the object', rules: ['box-profile-empty'], e: ev(0, [], '{"name":"Aaron"} x'), m: sign, b: PROFILE });
c({ why: 'a name that is only a byte order mark: JavaScript trims it, Kotlin does not', rules: ['box-profile-empty'], e: ev(0, [], json({ name: '﻿' })), m: sign, b: PROFILE });
c({ why: 'a name that is only a unit separator (U+001F): Kotlin calls it blank, JavaScript does not trim it', rules: ['box-profile-empty'], e: ev(0, [], json({ name: '\u001f' })), m: sign, b: PROFILE });

// Bookmarks and other private parts
const BM = es(4);
c({ why: 'bookmarks emptied, from 4', rules: ['marble-list-emptied'], e: ev(10003, []), prev: ev(10003, BM), m: ask('Empty your bookmarks (it has 4 bookmarks)') });
c({ why: 'bookmarks emptied, from 2', rules: ['marble-list-emptied'], e: ev(10003, []), prev: ev(10003, es(2)), m: sign,
  uncaught: 'A list of 1 or 2 emptied is never asked about.' });
c({ why: 'the 2026-11-18 shape: public bookmarks kept, the private part (NIP-44) dropped', rules: ['marble-private-emptied'], e: ev(10003, BM), prev: ev(10003, BM, SEALED), m: never('Empty your private bookmarks') });
c({ why: 'the private part in the old NIP-04 form dropped', rules: ['marble-private-emptied'], e: ev(10003, BM), prev: ev(10003, BM, NIP04), m: never('Empty your private bookmarks') });
c({ why: 'private part dropped and the public part emptied: the private part is named', rules: ['marble-private-emptied', 'marble-list-emptied'], e: ev(10003, []), prev: ev(10003, BM, SEALED), m: never('Empty your private bookmarks') });
c({ why: 'the private part replaced by a shorter one', rules: [], e: ev(10003, BM, 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='), prev: ev(10003, BM, SEALED), m: sign,
  uncaught: 'A private part rewritten without what it held looks like any edit until it is read. Should a signer that can decrypt compare the entries inside?' });
c({ why: 'the private part dropped, with no earlier version seen', rules: [], e: ev(10003, BM), m: sign,
  uncaught: 'A list is judged only against a version the signer saw: on a new phone, a box that has not signed this list yet, a set past the box\'s cap, or a site\'s own key, nothing is compared.' });
c({ why: 'a bookmark added, the private part kept', rules: [], e: ev(10003, [...BM, ['e', pk(99)]], SEALED), prev: ev(10003, BM, SEALED), m: sign });
c({ why: 'mute list: the private part dropped', rules: ['marble-private-emptied'], e: ev(10000, ps(1)), prev: ev(10000, ps(1), SEALED), m: never('Empty your private mute list') });
c({ why: 'mute list emptied, from 3', rules: ['marble-list-emptied'], e: ev(10000, []), prev: ev(10000, ps(3)), m: ask('Empty your mute list (it has 3 mutes)') });
c({ why: 'mute list emptied, from 2', rules: ['marble-list-emptied'], e: ev(10000, []), prev: ev(10000, ps(2)), m: sign,
  uncaught: 'Two muted people unmuted at once, with no question.' });
c({ why: 'a follow set emptied (its d tag kept)', rules: ['marble-list-emptied'], e: ev(30000, [['d', 'friends']]), prev: ev(30000, [['d', 'friends'], ...ps(5)]), m: ask('Empty your follow set (it has 5 persons)') });
c({ why: 'a bookmark set: the private part dropped', rules: ['marble-private-emptied'], e: ev(30003, [['d', 'reading'], ...es(2)]), prev: ev(30003, [['d', 'reading'], ...es(2)], SEALED), m: never('Empty your private bookmark set') });
c({ why: 'a list renamed: title and description are not entries', rules: [], e: ev(30001, [['d', 'x'], ['title', 'New'], ...es(3)]), prev: ev(30001, [['d', 'x'], ['title', 'Old'], ['description', 'd'], ...es(3)]), m: sign });

// Relays
c({ why: 'relay list: 2 of 3 dropped', rules: ['marble-relays-most'], e: ev(10002, rs('wss://a')), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c')), m: ask('Remove 2 of your 3 relays') });
c({ why: 'relay list: 1 of 3 dropped', rules: ['marble-relays-most'], e: ev(10002, rs('wss://a', 'wss://b')), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c')), m: sign });
c({ why: 'relay list: 2 of 4 dropped, exactly half', rules: ['marble-relays-most'], e: ev(10002, rs('wss://a', 'wss://b')), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c', 'wss://d')), m: ask('Remove 2 of your 4 relays') });
c({ why: 'relay list: 2 of 5 dropped, under half', rules: ['marble-relays-most'], e: ev(10002, rs('wss://a', 'wss://b', 'wss://c')), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c', 'wss://d', 'wss://e')), m: sign });
c({ why: 'relay list: only a trailing / changed', rules: ['marble-relays-most'], e: ev(10002, rs('wss://a/', 'wss://b')), prev: ev(10002, rs('wss://a', 'wss://b/')), m: sign });
c({ why: 'relay list: all 3 replaced by 3 others', rules: ['marble-relays-most'], e: ev(10002, rs('wss://x', 'wss://y', 'wss://z')), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c')), m: ask('Remove 3 of your 3 relays (and add 3)') });
c({ why: 'relay list emptied, from 3', rules: ['marble-list-emptied'], e: ev(10002, []), prev: ev(10002, rs('wss://a', 'wss://b', 'wss://c')), m: ask('Empty your relay list (it has 3 relays)') });
c({ why: 'relay list emptied, from 2', rules: ['marble-relays-most'], e: ev(10002, []), prev: ev(10002, rs('wss://a', 'wss://b')), m: ask('Remove 2 of your 2 relays') });
c({ why: 'relay list emptied, from 1', rules: [], e: ev(10002, []), prev: ev(10002, rs('wss://a')), m: sign,
  uncaught: 'With its only relay gone, nobody can find what the account writes, and neither side asks.' });
c({ why: 'search relays: 2 of 3 dropped (relay tags)', rules: ['marble-relays-most'], e: ev(10007, [['relay', 'wss://a']]), prev: ev(10007, [['relay', 'wss://a'], ['relay', 'wss://b'], ['relay', 'wss://c']]),
  m: ask('Remove 2 of your 3 relays') });

// Kinds nobody keeps
c({ why: 'DM relays (kind 10050) emptied', rules: [], e: ev(10050, []), prev: ev(10050, [['relay', 'wss://a'], ['relay', 'wss://b']]), m: sign,
  uncaught: 'Kind 10050 is not a kind Marble keeps, so it is never compared: with it emptied, NIP-17 messages to the account have nowhere to go.' });
c({ why: 'media servers (kind 10063) emptied', rules: [], e: ev(10063, []), prev: ev(10063, [['server', 'https://a.example'], ['server', 'https://b.example']]), m: sign,
  uncaught: 'Not a kept kind either: the account\'s pictures and files stop being found.' });
c({ why: 'app data (kind 30078) emptied', rules: [], e: ev(30078, [['d', 'marble/settings']], ''), prev: ev(30078, [['d', 'marble/settings']], SEALED), m: sign,
  uncaught: 'An app\'s own settings, sealed to the account: another app writing it back empty loses them. Likely each app\'s own business, but the 11-18 loss had this shape.' });

// Dated ahead
c({ why: 'a note dated 2099', rules: ['marble-ahead'], e: ev(1, [], 'hi', Y2099), m: ask('Note dated in the future (2099-01-01)') });
c({ why: 'a note 600 s ahead: not ahead yet', rules: ['marble-ahead'], e: ev(1, [], 'hi', NOW + 600), m: sign });
c({ why: 'a note 601 s ahead', rules: ['marble-ahead'], e: ev(1, [], 'hi', NOW + 601), m: ask('Note dated in the future (2027-01-15)') });
c({ why: 'a follow list 20 minutes ahead', rules: ['marble-ahead-list'], e: ev(3, ps(4), '', NOW + 1200), prev: ev(3, ps(3)), m: refuse('Follow list dated 2027-01-15: a version dated ahead would block every later change') });
c({ why: 'a follow list 5 minutes ahead (a fast clock)', rules: ['marble-ahead-list'], e: ev(3, ps(4), '', NOW + 300), prev: ev(3, ps(3)), m: sign });
c({ why: 'an empty profile dated 2099', rules: ['marble-ahead-list', 'box-profile-empty'], e: ev(0, [], '{}', Y2099), m: refuse('Profile dated 2099-01-01: a version dated ahead would block every later change') });
c({ why: 'a follow set dated 2099', rules: ['marble-ahead-list'], e: ev(30000, [['d', 'x'], ...ps(2)], '', Y2099), m: refuse('Follow set dated 2099-01-01: a version dated ahead would block every later change') });
c({ why: 'DM relays dated 2099: any replaceable kind', rules: ['marble-ahead-list'], e: ev(10050, [['relay', 'wss://a']], '', Y2099), m: refuse('Kind 10050 event dated 2099-01-01: a version dated ahead would block every later change') });
c({ why: 'a deletion by address dated 2099', rules: ['marble-ahead-delete-a'], e: ev(5, [['a', `30023:${ME}:my-essay`]], '', Y2099), m: refuse('Deletion dated 2099-01-01: it would delete every version until then') });
c({ why: 'a deletion by id dated 2099', rules: ['marble-ahead'], e: ev(5, [['e', pk(1)]], '', Y2099), m: ask('Deletion dated in the future (2099-01-01)') });
c({ why: 'deleting 5 by id, dated 2099', rules: ['marble-ahead', 'box-delete-5'], e: ev(5, es(5), '', Y2099), m: ask('Deletion dated in the future (2099-01-01)') });
c({ why: 'vanish dated 2099', rules: ['marble-ahead', 'box-vanish'], e: ev(62, [['relay', 'ALL_RELAYS']], '', Y2099), m: never('Request to vanish dated in the future (2099-01-01)') });
c({ why: 'deleting the bookmarks by k, dated 2099: dated ahead, and level 2 as it would be dated now', rules: ['marble-ahead', 'marble-delete-list'], e: ev(5, [['e', pk(1)], ['k', '10003']], '', Y2099),
  m: never('Deletion dated in the future (2099-01-01)') });

export function build() {
  return {
    about: 'Shared cases for "is this event hard to undo?" Made by tools/hard-to-undo-vectors.mjs; run by test/hard-to-undo-vectors.test.ts (Keykin) and HardToUndoVectorsTest (Marble). '
      + '`answers` is what each implementation answers today, with `level` (1: Are you sure?, 2: never by accident; null when nobody is asked); `expect` is the box\'s decision and `level` its level, since the box is the authority (Marble may ask more on top). `prev` is the last version of that list or profile the signer saw (null: none). `now` is the signer\'s clock. '
      + 'Events are unsigned; their pubkey is a stand-in.',
    now: NOW,
    implementations: {
      [B]: 'Keykin box/box.ts #sign with src/destructive.ts judge(event, prev, now). ask, level 1: the box answers needs_tap unless the request says tapped: true. ask, level 2: it answers needs_fingerprint '
        + '(no_chip_key to a device with no chip key) unless the request carries a valid fp by the asking device\'s chip key, as for an account change; tapped alone never signs it. refuse: it answers dated_ahead. All carry says as why',
      [M]: 'Marble android/signer/src/main/java/cc/aaro/cosign/core/Policy.kt, refuse(e, now) then question(e, prev, now): its own check on top of the box, and its only one with no box in the signature',
    },
    outcomes: {
      marble: 'Marble Android with a box. signs: nobody is asked. asks: the phone asks once (in its own words when its rules ask, else in the box\'s), and Yes signs with tapped. '
        + 'fingerprint: the same question, and Yes goes on to the fingerprint, sent as fp for the box to check (level 2 on either side). refuses: never signed.',
      marbleAlone: 'Marble Android with no box in the signature (the whole key on the phone, or another device helping while the box is off): its own rules only. '
        + 'asks: Yes or No. fingerprint: Yes, then the phone\'s fingerprint prompt (none on a phone with no fingerprint set up). refuses: never signed.',
      mac: 'Marble for the Mac. signs: nobody is asked. asks: the box answers needs_tap, the Mac asks with the box\'s words, and Yes sends it again with tapped. '
        + 'phone: the box answers needs_fingerprint; the Mac shows the box\'s words and that this is done from the phone, with no Yes, and sends nothing more. refuses: never signed.',
      keykinDevices: 'Devices that cannot ask a person (the NIP-46 bunker in src/nip46.ts, the command-line device). needs_tap, needs_fingerprint or dated_ahead: refused, and the error carries the box\'s words '
        + '(for needs_fingerprint, also that it is done from the phone). signs: signed.',
    },
    rules,
    cases,
  };
}

// ── Writing, copying, checking ──
const repo = resolve(fileURLToPath(new URL('..', import.meta.url)));
const file = join(repo, 'vectors', 'hard-to-undo.json');
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
function commit() {
  try {
    const head = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['-C', repo, 'status', '--porcelain', '--', 'vectors/hard-to-undo.json'], { encoding: 'utf8' }).trim();
    return head + (dirty ? ' (with uncommitted changes in vectors/hard-to-undo.json)' : '');
  } catch { return 'unknown'; }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args[0] === '--check' && args.length === 2) {
    const dir = resolve(args[1]);
    const src = join(dir, 'hard-to-undo.SOURCE');
    if (!existsSync(src)) { console.error(`${dir}: no hard-to-undo.SOURCE`); process.exit(1); }
    const [from, line] = readFileSync(src, 'utf8').split('\n');
    const recorded = (line || '').split('  ')[0];
    const problems = [];
    if (sha(join(dir, 'hard-to-undo.json')) !== recorded) problems.push('the copy was edited after it was made');
    if (sha(file) !== recorded) problems.push('the copy differs from this checkout\'s vectors/hard-to-undo.json');
    if (problems.length) { console.error(`${dir} (${from}):\n  ` + problems.join('\n  ')); process.exit(1); }
    console.log(`${dir}: the same as this checkout's vectors/hard-to-undo.json (${from})`);
  } else if (args.length === 0 || (args[0] === '--copy' && args.length === 2)) {
    const out = build();
    writeFileSync(file, JSON.stringify(out, null, 1) + '\n');
    const n = (d) => out.cases.filter((x) => x.expect === d).length;
    console.log(`vectors/hard-to-undo.json: ${out.cases.length} cases (${n('sign')} sign, ${n('ask')} ask, ${n('refuse')} refuse, ${out.cases.filter((x) => x.uncaught).length} uncaught), ${out.rules.length} rules`);
    if (args[0] === '--copy') {
      const dir = resolve(args[1]);
      copyFileSync(file, join(dir, 'hard-to-undo.json'));
      writeFileSync(join(dir, 'hard-to-undo.SOURCE'), `keykin ${commit()}\n${sha(file)}  vectors/hard-to-undo.json\n`);
      console.log(`copied to ${dir}`);
    }
  } else { console.error('usage: node tools/hard-to-undo-vectors.mjs [--copy <dir> | --check <dir>]'); process.exit(2); }
}
