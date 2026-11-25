#!/usr/bin/env node
// Writes calendar/vectors/calendar.json: shared cases for the calendar module (KIST calendar profile §2), which the
// JS (calendar/js/calendar.js) and Kotlin (calendar/kotlin/Calendar.kt) copies must both give.
//
//   node tools/calendar-vectors.mjs
//
// Each case is built here with the JS module, and what it must show is checked here by hand (the asserts below), so
// a change in the module that changes a rule fails here first. Every implementation then has to give the same bytes:
// test/calendar-vectors.test.ts runs the JS, calendar/test-kotlin runs the Kotlin.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { canon, stamp, merge, instanceView, instanceId, importId, settingsId } from '../calendar/js/calendar.js';

const MAC = 'a1b2c3d4', PIXEL = '0f0e0d0c', WEB = '77777777';
const T = 1795000000000; // 2026-11-17, ms
const MIN = 60000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const SERIES = '5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e', VAULT = 'ab'.repeat(32);
const tz = 'America/Denver';
const at = (local) => ({ local, tz });

const EVENT = {
  meta: {
    kind: 'event', uid: 'dentist@kist', title: 'Dentist', start: at('2026-12-01T09:30:00'), end: at('2026-12-01T10:30:00'),
    all_day: false, rrule: null, exdates: [], rdates: [], location: 'Main St', url: null, status: 'confirmed', busy: true,
    alerts: [{ before: 900 }], attendees: [], organizer: null, attach: [], seq: 0, ics: '',
  },
  data: { text: 'Bring the form' },
};
const DELETED = { meta: { kind: 'event' }, data: null, deleted: true };
const edit = (v, fields, data) => ({ meta: { ...v.meta, ...fields }, data: data === undefined ? v.data : data });

const stamps = [], merges = [];
function S(name, why, prev, next, clock, device) {
  const out = stamp(prev, next, { clock, device });
  stamps.push({ name, why, prev, next, clock, device, expect: out });
  return out;
}
function M(name, why, versions) {
  const out = merge(versions);
  merges.push({ name, why, versions, expect: out, canon: canon(out) });
  return out;
}

// ── a new event, made on the Mac ──
const base = S('new event', 'a new entry stamps every field it has, at the clock', null, EVENT, T, MAC);
assert.deepEqual(base.meta.edited.title, { t: T, d: MAC });
assert.deepEqual(base.meta.edited.data, { t: T, d: MAC });
assert.equal(Object.keys(base.meta.edited).length, Object.keys(EVENT.meta).length); // every field but kind, plus data

// ── 1. a stale device changing one field ──
const mTitle = S('mac renames', 'only the changed field gets a new stamp', base, edit(base, { title: 'Dentist, Dr Lee' }), T + HOUR, MAC);
assert.deepEqual(mTitle.meta.edited.title, { t: T + HOUR, d: MAC });
assert.deepEqual(mTitle.meta.edited.location, { t: T, d: MAC });
const mPlace = S('mac moves it', 'only the changed field gets a new stamp', mTitle, edit(mTitle, { location: '12 Oak Ave' }), T + 2 * HOUR, MAC);
const stale = S('stale pixel changes the time', 'the Pixel still has the first version; it stamps only the time',
  base, edit(base, { start: at('2026-12-01T11:00:00'), end: at('2026-12-01T12:00:00') }), T + 3 * HOUR, PIXEL);
assert.deepEqual(stale.meta.edited.title, { t: T, d: MAC });
const m1 = M('stale device', 'the stale Pixel wins only the time it changed; the Mac keeps its newer title and place', [mPlace, stale]);
assert.equal(m1.meta.title, 'Dentist, Dr Lee');
assert.equal(m1.meta.location, '12 Oak Ave');
assert.deepEqual(m1.meta.start, at('2026-12-01T11:00:00'));
assert.deepEqual(m1.data, { text: 'Bring the form' });

// ── 2. a clock behind: + 1 ──
const mA = S('mac renames (clock right)', '', base, edit(base, { title: 'Dentist 2' }), T + 10 * MIN, MAC);
const slow = S('slow pixel renames after seeing it', 'the Pixel clock is an hour behind; t = the seen t + 1',
  mA, edit(mA, { title: 'Dentist 3' }), T - HOUR, PIXEL);
assert.deepEqual(slow.meta.edited.title, { t: T + 10 * MIN + 1, d: PIXEL });
const slowOld = S('slow pixel changes a field untouched since the start', 't = max(clock, T + 1), past what it saw',
  mA, edit(mA, { busy: false }), T - HOUR, PIXEL);
assert.deepEqual(slowOld.meta.edited.busy, { t: T + 1, d: PIXEL });
const webPlace = S('web moves it meanwhile', '', mA, edit(mA, { location: 'Clinic' }), T + 11 * MIN, WEB);
const m2 = M('clock behind', 'the slow Pixel\'s title still beats the one it saw; the web\'s place stays', [slow, webPlace]);
assert.equal(m2.meta.title, 'Dentist 3');
assert.equal(m2.meta.location, 'Clinic');

// ── 3. a clock ahead ──
const fast = S('fast pixel renames', 'the Pixel clock is two days ahead', base, edit(base, { title: 'From the future' }), T + 2 * DAY, PIXEL);
const macLater = S('mac renames an hour later', '', base, edit(base, { title: 'Real title' }), T + HOUR, MAC);
const m3 = M('clock ahead', 'a fast clock wins the same-field clash it is part of (the loser stays in history)', [macLater, fast]);
assert.equal(m3.meta.title, 'From the future');
const fixed = S('mac renames after seeing it', 't = the fast stamp + 1, so the next edit still wins', m3, edit(m3, { title: 'Real title' }), T + 2 * HOUR, MAC);
assert.deepEqual(fixed.meta.edited.title, { t: T + 2 * DAY + 1, d: MAC });
const m3b = M('clock ahead, then fixed', 'the edit made after seeing the fast one wins', [fixed, fast]);
assert.equal(m3b.meta.title, 'Real title');

// ── 4. a same-field clash at the same t: d decides ──
const cMac = S('mac at t', '', base, edit(base, { title: 'Mac title' }), T + 5000, MAC);
const cPixel = S('pixel at the same t', '', base, edit(base, { title: 'Pixel title' }), T + 5000, PIXEL);
const m4 = M('same t, d decides', 'equal t: the higher d wins (a1b2c3d4 > 0f0e0d0c)', [cPixel, cMac]);
assert.equal(m4.meta.title, 'Mac title');

// ── 5. edit against delete ──
const pEdit = S('pixel adds a note', '', base, edit(base, {}, { text: 'Bring the form and the card' }), T + MIN, PIXEL);
const m5 = M('edit beats delete', 'one version is a deletion: the merge is the edit, never the deletion', [DELETED, pEdit]);
assert.equal(m5.deleted, false);
assert.deepEqual(m5.data, { text: 'Bring the form and the card' });
const cancel = S('mac cancels', 'a cancel is a field like any other', base, edit(base, { status: 'cancelled' }), T + 2 * MIN, MAC);
const m5b = M('cancel and edit at once', 'a cancelled event with the edit in it, not a gone one', [cancel, pEdit]);
assert.equal(m5b.meta.status, 'cancelled');
assert.deepEqual(m5b.data, { text: 'Bring the form and the card' });

// ── 6. two deletions ──
const m6 = M('two deletions', 'every version is a deletion: one deletion', [DELETED, DELETED]);
assert.equal(m6.deleted, true);
const m6b = M('two edits and two deletions', 'the edits merge among themselves; the deletions are dropped', [DELETED, cancel, DELETED, pEdit]);
assert.deepEqual(m6b, m5b);

// ── 7. an instance edit against a series edit ──
const original = at('2026-12-08T09:30:00');
const iid = instanceId(SERIES, original);
const series = S('weekly series', '', null, edit(EVENT, { uid: 'standup@kist', title: 'Standup', rrule: 'FREQ=WEEKLY;BYDAY=TU' }), T, MAC);
const iPixel = S('pixel moves one Tuesday', 'an instance holds only what differs; the id is fixed by the series and the original time', null,
  { meta: { kind: 'instance', series: SERIES, original, start: at('2026-12-08T10:00:00'), end: at('2026-12-08T10:30:00') }, data: null }, T + HOUR, PIXEL);
const iMac = S('mac moves the same Tuesday to a room', 'made offline at the same time, so the same entry', null,
  { meta: { kind: 'instance', series: SERIES, original, location: 'Room 4' }, data: null }, T + HOUR + 1, MAC);
const sMac = S('mac renames the series', '', series, edit(series, { title: 'Team standup' }), T + 2 * HOUR, MAC);
const mi = M('the same instance from two devices', 'both changes to that Tuesday are kept', [iPixel, iMac]);
assert.equal(mi.meta.location, 'Room 4');
assert.deepEqual(mi.meta.start, at('2026-12-08T10:00:00'));
const views = [];
const V = (name, why, s, i) => { const out = instanceView(s.meta, i.meta); views.push({ name, why, series: s.meta, instance: i.meta, expect: out }); return out; };
const view = V('series renamed, instance moved', 'the instance shows the series\' new title with its own time and place', sMac, mi);
assert.equal(view.title, 'Team standup');
assert.equal(view.location, 'Room 4');
assert.equal(view.rrule, null);
const iTitle = S('pixel renames that Tuesday', '', mi, edit(mi, { title: 'Standup at the cafe', location: null }), T + 3 * HOUR, PIXEL);
const view2 = V('instance renamed, series renamed', 'the instance\'s own title stays; a null field falls back to the series', sMac, iTitle);
assert.equal(view2.title, 'Standup at the cafe');
assert.equal(view2.location, 'Main St');

// ── 8. the merge of a merge is stable ──
assert.deepEqual(M('merge of a merge', 'merging a merge alone gives it back', [m1]), m1);
assert.deepEqual(M('merge with one of its inputs', 'a merge already holds what its inputs had', [m1, stale]), m1);
assert.deepEqual(M('merge with all its inputs', '', [mPlace, m1, stale]), m1);

// ── other rules ──
const mRemove = S('mac clears the url field', 'a field taken out is a change: it keeps a stamp and no value', base,
  { meta: Object.fromEntries(Object.entries(base.meta).filter(([k]) => k !== 'url')), data: base.data }, T + MIN, MAC);
assert.ok(!('url' in mRemove.meta) && mRemove.meta.edited.url);
const m9 = M('a removed field', 'the newer removal beats the older value', [mRemove, pEdit]);
assert.ok(!('url' in m9.meta));
const same1 = { meta: { kind: 'event', title: 'B', edited: { title: { t: T, d: MAC } } }, data: null };
const same2 = { meta: { kind: 'event', title: 'A', edited: { title: { t: T, d: MAC } } }, data: null };
const same3 = { meta: { kind: 'event', edited: { title: { t: T, d: MAC } } }, data: null };
assert.equal(M('equal stamps, different values', 'never in practice: the higher canonical JSON wins, so every device agrees', [same2, same1]).meta.title, 'B');
assert.equal(M('equal stamps, value and no value', 'a value beats no value, so nothing is dropped', [same3, same2]).meta.title, 'A');
const range = S('a free range', 'DMs: a range is an event with only a start, an end and busy', null,
  { meta: { kind: 'event', start: at('2026-12-05T18:00:00'), end: at('2026-12-05T23:00:00'), busy: false }, data: null }, T, PIXEL);
const partial = { meta: { kind: 'event', busy: true, edited: { busy: { t: T + MIN, d: MAC } } } };
const m10 = M('a version with only the changed field', 'a version may carry just the fields it changed; the rest come from the others', [range, partial]);
assert.equal(m10.meta.busy, true);
assert.deepEqual(m10.meta.start, at('2026-12-05T18:00:00'));
const bad = { meta: { kind: 'event', title: 'Odd', edited: { title: { t: -5, d: 'nothex!!' } } }, data: null };
assert.equal(M('a malformed stamp', 'a malformed stamp counts as no stamp, and is left out of the merge', [bad, range]).meta.edited.title, undefined);
const set1 = S('settings, mac', '', null, { meta: { kind: 'settings', color: '#3b82f6', default_alerts: [{ before: 600 }], tz, subscriptions: [] } }, T, MAC);
const set2 = S('settings, pixel recolors', '', set1, edit(set1, { color: '#ef4444' }), T + MIN, PIXEL);
const set3 = S('settings, mac adds a subscription', '', set1, edit(set1, { subscriptions: [{ url: 'https://example.org/holidays.ics', name: 'Holidays', color: '#22c55e' }] }), T + 2 * MIN, MAC);
const ms = M('settings', 'settings merge the same way', [set2, set3]);
assert.equal(ms.meta.color, '#ef4444');
assert.equal(ms.meta.subscriptions.length, 1);

// ── canonical JSON ──
const canons = [
  { '\u{1F600}': 1, '￿': 2, 'é': 3, a: 4, B: 5, '': 6 },
  ['\u0000\u0001\u001f', '"\\/', '\b\f\n\r\t', '  ', '\u007f', 'é\u{1F600}', '\ud800', '\udc00x'],
  { n: [0, -1, 9007199254740991, -9007199254740991], b: [true, false, null], nest: { z: {}, a: [] } },
].map((value) => ({ value, expect: canon(value) }));
assert.equal(canons[0].expect, '{"":6,"B":5,"a":4,"é":3,"\u{1F600}":1,"￿":2}');

// ── entry ids ──
const ids = [
  { fn: 'instance', series: SERIES, original, expect: iid },
  { fn: 'instance', series: SERIES, original: { date: '2026-12-08' }, expect: instanceId(SERIES, { date: '2026-12-08' }) },
  { fn: 'instance', series: SERIES, original: { utc: 1795000000 }, expect: instanceId(SERIES, { utc: 1795000000 }) },
  { fn: 'import', vault: VAULT, uid: '040000008200E00074C5B7101A82E008@outlook.com', expect: importId(VAULT, '040000008200E00074C5B7101A82E008@outlook.com') },
  { fn: 'import', vault: VAULT, uid: 'événement-1', expect: importId(VAULT, 'événement-1') },
  { fn: 'settings', vault: VAULT, expect: settingsId(VAULT) },
];
assert.notEqual(ids[0].expect, ids[1].expect);

const out = {
  about: 'Shared cases for the calendar module (KIST calendar profile §2). Written by tools/calendar-vectors.mjs; '
    + 'the JS and Kotlin copies must give `expect` exactly, and `canon` byte for byte. Times are ms; devices are 8 hex.',
  stamp: stamps, merge: merges, instance_view: views, canon: canons, ids,
};
writeFileSync(new URL('../calendar/vectors/calendar.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`calendar/vectors/calendar.json: ${stamps.length} stamp, ${merges.length} merge, ${views.length} view, ${canons.length} canon, ${ids.length} id cases`);
