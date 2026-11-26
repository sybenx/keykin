# calendar: the shared calendar module

The one copy of the calendar rules that Marble (personal calendar, kept in KIST) and DMs (plans and free times in a
chat) both use: the event format's entry ids, stamping a new version, and merging versions by field so nobody ever
picks between two. The rules are KIST's calendar profile, §2 (`~/kist`, `proposals/calendar-profile.md` on branch
`calendar-profile`). It knows nothing about KIST, Nostr or DMs: an app passes versions in and gets versions out, and
keeps and sends them its own way.

Two copies that give the same bytes for the same input, and the cases both pass:

| Part | Files | For |
|---|---|---|
| `js/` | `calendar.js`, `sha256.js` | a web app or Node. Plain ES modules, no packages. |
| `kotlin/` | `Calendar.kt`, `CalendarRows.kt` (package `cc.aaro.calendar`) | Android or any JVM. Only the Kotlin and Java standard libraries. |
| `android/` | `AndroidCalendar.kt` | Android: writes entries into the phone's calendar. Needs `kotlin/` beside it. |
| `vectors/` | `calendar.json` | an app's own tests, if it wants them |

`test-kotlin/` runs the vectors and the row tests against `kotlin/` on the JVM; `test-android/` runs `android/`
against a real calendar provider on an emulator. Neither is copied.

Not here yet: recurrence expansion, iCalendar reading and writing, reading edits back from the phone's calendar.

## What it does

A **version** is `{meta, data, deleted}`, as a KIST put carries them: `meta` has `kind` (`event`, `instance`,
`settings`) and the fields, `data` is the notes (`{"text": …}`) or null, and a deletion is `deleted: true` with
`meta` `{kind}` only. Each field of `meta` other than `kind` and `edited`, and `data`, has a stamp in `meta.edited`:
`{"t": <ms>, "d": "<8 lowercase hex>"}` (KIST: the writer's dvk; DMs: whatever short id a device has).

- **`stamp(prev, next, {clock, device})`** (Kotlin: `Calendar.stamp(prev, next, clock, device)`): the version to
  write. Fields whose value changed since `prev` get `{t: max(clock, their t in prev + 1), d: device}`; the rest
  keep `prev`'s stamps. `prev` null (or a deletion): a new entry, every field it has is stamped at `clock`.
- **`merge(versions)`**: the one version every device computes from an entry's current versions. Each field takes
  the value with the highest stamp; `edited` is the per-field highest; an edit beats a delete; all deletions give a
  deletion. Any order gives the same result, and merging a merge (alone or with any of its inputs) gives it back.
  Write `canon(result)`: that is the same bytes on every device.
- **`canon(value)`** / **`parse(text)`** (Kotlin: `CalJson`): RFC 8785 canonical JSON for integer-only JSON, and a
  reader that refuses floats. Kotlin's JSON values are plain `Map`/`List`/`String`/`Long`/`Boolean`/null.
- **`instanceView(series, instance)`**: what a changed occurrence shows: the series' fields under the instance's
  non-null ones, with no recurrence.
- **`instanceId(seriesEntry, original)`**, **`importId(vaultId, uid)`**, **`settingsId(vaultId)`**: the fixed entry
  ids (`nostr-vault/instance/1`, `cal-import/1`, `cal-settings/1` tagged hashes), checked against KIST's own `TH`.
- **`compareStamps`**, **`taggedHash`**.

A version may carry only some fields (DMs sends just what changed): a field it lacks is no value at no stamp, and the
merge takes it from the others.

## The phone's calendar (Android, writing half)

`AndroidCalendar(contentResolver, accountName, accountType)` puts entries into Android's own calendar
(CalendarContract), so the phone's calendar app, widgets and alerts show them and they follow later changes.

- **One calendar per source**: `Source(key, name, color, tz, access)`. `key` names it for good (`dms-plans`, a vault
  id); name and color can change. DMs passes `ACCOUNT_TYPE_LOCAL` (the default), which needs no account of its own;
  Marble passes its calendar account.
- **`sync(source, entries)`**: entry id to current merged version. Each event becomes a row keyed by its entry id
  (`_sync_id`), a changed instance becomes an exception row tied to its series, deletions and missing entries are
  removed, and a row already right is not touched (a hash of what was written is in `sync_data1`). Running it again
  changes nothing. `only = setOf(ids)` looks at just those entries, for an app that sends what changed.
- **Alerts** become reminders (minutes before); an `at` alert counts only on a single event. Notes go in the
  description. An event in a zone the phone doesn't know is shown in UTC rather than dropped.
- **Calendars are read-only in the phone by default** (`access` = `CAL_ACCESS_READ`), so nobody types an edit there
  that would then be written over. Once reading back exists, a source can pass `CAL_ACCESS_OWNER`.
- **The seam for reading back**: Android marks a row the calendar app changed as dirty. `sync` holds such rows
  (`Result.held`) instead of writing over them; `changedInPhone(key)` lists them with `sync_data2`, the tag the
  caller passed for the version the row showed (`tags = mapOf(entry to ver)`). The reading half compares the row
  with that version, stamps what differs (`stamp`), and then syncs with `dirty = Dirty.OVERWRITE`.
- **`removeCalendar(key)`** takes the calendar and its rows out of the phone.

Pure parts, JVM-tested: `CalendarRows.rows(entries)` (entries to row values, CalendarContract column names) and
`CalendarRows.plan(rows, existing)` (what to add, change and remove).

Not written to the phone yet: attendees, the `url` field, attachments, and `rdates` on all-day events beyond their
date.

## Readings the spec leaves open (picked so nothing is lost; for the spec)

1. **`data` is stamped as `edited.data`.** §2.4 stamps "each field" and the notes live in `data`, outside `meta`.
   Without a stamp two devices' notes could not merge, so `data` is a field named `data`. No `meta` field may be
   named `data`.
2. **Equal stamps with different values** (one device writing twice from a stale copy within the same ms): a value
   beats no value, then the higher canonical JSON (compared by UTF-16 code units) wins. Never in practice, but every
   device must agree.
3. **A field taken out** (absent from `next` where `prev` had it) is a change: it gets a stamp and no value, and that
   stamp competes like any other. Absent and `null` are different values.
4. **A malformed stamp** (not `{t: whole ms ≥ 0, d: 8 lowercase hex}`) counts as no stamp and is dropped from the
   merge's `edited`.
5. **Versions of different kinds** in one entry cannot happen within the profile; `merge` refuses them (throws) and
   the app keeps them as they are rather than dropping one.
6. **Ids hash raw bytes**: the series entry as its 16 bytes and the vault id as its 32, as KIST's other tagged
   hashes do with ids.
7. **The `+ 1` rule uses the stamp in the version the edit was made on** (`prev`), which for a CalDAV PUT is the
   version its `If-Match` names (§3.2).
8. **The merge output always has `edited`** (empty for a version with no stamps) and `data` (null when no version
   has one); a deletion is exactly `{meta: {kind}, data: null, deleted: true}`.
9. **Unknown fields** in `meta` are stamped and merged like known ones, so a newer app's fields survive an older one.

## Taking a copy

```bash
node tools/calendar-copy.mjs js ../my-app/web/calendar
```

```bash
node tools/calendar-copy.mjs kotlin ../my-app/app/src/main/java/cc/aaro/calendar
```

```bash
node tools/calendar-copy.mjs android ../my-app/app/src/main/java/cc/aaro/calendar/android
```

```bash
node tools/calendar-copy.mjs --check kotlin ../my-app/app/src/main/java/cc/aaro/calendar
```

Each copy gets a `SOURCE` with the Keykin commit and a sha256 per file; `--check` exits 1 naming any file edited in
the copy or changed here since. Edit here, then copy again; never edit the copy. A folder with files and no
`SOURCE` is left alone.

## Shared cases

`vectors/calendar.json` is written by `node tools/calendar-vectors.mjs`, which builds each case with the JS module
and checks by hand what it must show (a stale device changing one field, a clock behind and the `+ 1`, a clock ahead,
a same-field clash decided by `d`, edit against delete, two deletions, an instance edit against a series edit, the
merge of a merge, a field taken out, a version with only its changed field, settings, canonical JSON, the ids).

```bash
node --test test/calendar-vectors.test.ts
```

```bash
cd calendar/test-kotlin && JAVA_HOME=$(/usr/libexec/java_home -v 17) ../../android/gradlew -p . test
```

Both run every merge case in every rotation and reversed, and check that merging the result again changes nothing.

The phone's calendar, on one running emulator (it adds and then removes a test calendar):

```bash
cd calendar/test-android && JAVA_HOME=$(/usr/libexec/java_home -v 17) ../../android/gradlew -p . connectedDebugAndroidTest
```
