// The shared calendar module: turning merged calendar entries into the rows of the phone's calendar
// (Android's CalendarContract), and working out which rows to add, change or remove. Pure Kotlin, no Android
// classes, so it runs in JVM tests; calendar/android/AndroidCalendar.kt does the writing on a phone.
//
// Column names are CalendarContract's own values ("dtstart", "eventTimezone", ...), checked on an emulator by
// calendar/test-android.
package cc.aaro.calendar

import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

@Suppress("UNCHECKED_CAST")
object CalendarRows {
    /** One event row: `entry` is its entry id (kept in `_sync_id`), `series` the series entry for a changed instance. */
    data class Row(
        val entry: String,
        val series: String?,
        val values: Map<String, Any?>,
        /** Minutes before the start, for CalendarContract.Reminders (METHOD_ALERT). */
        val reminders: List<Int>,
        /** A hash of `values` and `reminders`, kept in `sync_data1`: equal means the row is already right. */
        val fingerprint: String,
    )

    /** A row already in the phone's calendar, as read back. `dirty`: changed in the phone (not by us). */
    data class Existing(val id: Long, val entry: String?, val fingerprint: String?, val dirty: Boolean, val deleted: Boolean)

    sealed class Op {
        data class Insert(val row: Row) : Op()
        data class Update(val id: Long, val row: Row) : Op()
        data class Delete(val id: Long, val entry: String?) : Op()
    }

    /**
     * What to do with rows changed in the phone's calendar app. HOLD leaves them alone (and lists them in
     * Plan.held), so an edit made there is never written over before the reading-back half exists to merge it.
     */
    enum class Dirty { HOLD, OVERWRITE }

    data class Plan(val ops: List<Op>, val held: List<String>, val skipped: List<String>)

    // CalendarContract values, as plain numbers
    const val STATUS_TENTATIVE = 0
    const val STATUS_CONFIRMED = 1
    const val STATUS_CANCELED = 2
    const val AVAILABILITY_BUSY = 0
    const val AVAILABILITY_FREE = 1

    /**
     * The rows for an entry set: entry id → its current (merged) version, {meta, data, deleted}. Deleted entries and
     * kinds other than `event` and `instance` give no row. A changed instance needs its series in the set; one
     * without it is listed in `skipped` (by `plan`). `tags` (optional, entry id → text, such as the version id the row
     * shows) goes in `sync_data2`, for reading the phone's edits back later.
     */
    fun rows(entries: Map<String, Map<String, Any?>>, tags: Map<String, String> = emptyMap()): Pair<List<Row>, List<String>> {
        val out = ArrayList<Row>()
        val skipped = ArrayList<String>()
        for (id in entries.keys.sorted()) {
            val v = entries.getValue(id)
            if (v["deleted"] == true) continue
            val meta = v["meta"] as? Map<String, Any?> ?: continue
            when (meta["kind"]) {
                "event" -> eventRow(id, null, meta, v["data"], null, tags[id])?.let(out::add) ?: skipped.add(id)
                "instance" -> {
                    val sid = meta["series"] as? String
                    val series = sid?.let { entries[it] }
                    val sMeta = series?.get("meta") as? Map<String, Any?>
                    if (series == null || series["deleted"] == true || sMeta?.get("kind") != "event") { skipped.add(id); continue }
                    val view = Calendar.instanceView(sMeta, meta)
                    // notes: the instance's own, else the series'
                    val data = v["data"] ?: series["data"]
                    eventRow(id, sid, view, data, meta["original"], tags[id])?.let(out::add) ?: skipped.add(id)
                }
            }
        }
        return out to skipped
    }

    /**
     * The changes that make the phone's rows (`existing`, every row of this calendar) match `rows`. With `only` set,
     * rows of other entries are left as they are (for an app that sends just what changed). Removals come first,
     * then series and single events, then changed instances (which need their series row).
     */
    fun plan(rows: List<Row>, existing: List<Existing>, only: Set<String>? = null, dirty: Dirty = Dirty.HOLD, skipped: List<String> = emptyList()): Plan {
        val want = rows.filter { only == null || it.entry in only }.associateBy { it.entry }
        val deletes = ArrayList<Op>()
        val held = ArrayList<String>()
        val have = HashMap<String, Existing>()
        for (e in existing.sortedBy { it.id }) {
            val mine = only == null || e.entry in only
            if (!mine) continue
            if (e.dirty && dirty == Dirty.HOLD) { e.entry?.let(held::add); if (e.entry != null) have[e.entry] = e; continue }
            if (e.entry == null || e.entry !in want || e.entry in have || e.deleted) { deletes.add(Op.Delete(e.id, e.entry)); continue }
            have[e.entry] = e
        }
        val first = ArrayList<Op>()
        val later = ArrayList<Op>()
        for (r in want.values.sortedBy { it.entry }) {
            val e = have[r.entry]
            val op = when {
                e == null -> Op.Insert(r)
                e.dirty && dirty == Dirty.HOLD -> null
                e.fingerprint == r.fingerprint -> null
                else -> Op.Update(e.id, r)
            } ?: continue
            if (r.series == null) first.add(op) else later.add(op)
        }
        return Plan(deletes + first + later, held.distinct().sorted(), skipped)
    }

    // ── one row ──

    private val UTC: ZoneId = ZoneOffset.UTC
    private val STAMP: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(UTC)

    /** A time of the format: ms since 1970, its zone for the row, and whether it is a date. Null when unreadable. */
    data class When(val ms: Long, val tz: String, val date: Boolean)

    fun readTime(t: Any?): When? {
        val m = t as? Map<*, *> ?: return null
        return try {
            when {
                m["date"] is String -> When(LocalDate.parse(m["date"] as String).atStartOfDay(UTC).toInstant().toEpochMilli(), "UTC", true)
                m["utc"] is Number -> When((m["utc"] as Number).toLong() * 1000, "UTC", false)
                m["local"] is String -> {
                    val zone = (m["tz"] as? String)?.let { runCatching { ZoneId.of(it) }.getOrNull() }
                    val local = LocalDateTime.parse(m["local"] as String)
                    // a zone this phone does not know: read as UTC rather than drop the event
                    When(local.atZone(zone ?: UTC).toInstant().toEpochMilli(), if (zone != null) m["tz"] as String else "UTC", false)
                }
                else -> null
            }
        } catch (_: Exception) { null }
    }

    private const val DAY = 86_400_000L

    private fun eventRow(entry: String, series: String?, meta: Map<String, Any?>, data: Any?, original: Any?, tag: String?): Row? {
        val start = readTime(meta["start"]) ?: return null
        val allDay = meta["all_day"] == true || start.date
        // an all-day event starts at midnight UTC on its date
        val s = if (allDay && !start.date) When(Instant.ofEpochMilli(start.ms).atZone(ZoneId.of(start.tz)).toLocalDate().atStartOfDay(UTC).toInstant().toEpochMilli(), "UTC", true) else start
        val tz = if (allDay) "UTC" else s.tz
        var end = readTime(meta["end"])?.ms ?: s.ms
        if (allDay) {
            end = Instant.ofEpochMilli(end).atZone(UTC).toLocalDate().atStartOfDay(UTC).toInstant().toEpochMilli()
            if (end <= s.ms) end = s.ms + DAY
        } else if (end < s.ms) end = s.ms
        val rrule = (meta["rrule"] as? String)?.takeIf { it.isNotBlank() && series == null }
        val rdates = if (series == null) times(meta["rdates"]) else emptyList()
        val exdates = if (series == null) times(meta["exdates"]) else emptyList()
        val repeats = rrule != null || rdates.isNotEmpty()
        val v = LinkedHashMap<String, Any?>()
        v["_sync_id"] = entry
        v["title"] = meta["title"] as? String
        v["dtstart"] = s.ms
        v["eventTimezone"] = tz
        v["allDay"] = if (allDay) 1 else 0
        if (repeats) {
            v["dtend"] = null
            v["duration"] = if (allDay) "P${(end - s.ms) / DAY}D" else "P${(end - s.ms) / 1000}S"
        } else {
            v["dtend"] = end
            v["duration"] = null
        }
        v["eventEndTimezone"] = if (repeats) null else tz
        v["rrule"] = rrule
        v["rdate"] = rdates.takeIf { it.isNotEmpty() }?.joinToString(",") { STAMP.format(Instant.ofEpochMilli(it)) }
        v["exdate"] = exdates.takeIf { it.isNotEmpty() }?.joinToString(",") { STAMP.format(Instant.ofEpochMilli(it)) }
        v["eventLocation"] = meta["location"] as? String
        v["description"] = ((data as? Map<*, *>)?.get("text") as? String)
        v["eventStatus"] = when (meta["status"]) { "tentative" -> STATUS_TENTATIVE; "cancelled" -> STATUS_CANCELED; "confirmed" -> STATUS_CONFIRMED; else -> null }
        v["availability"] = if (meta["busy"] == false) AVAILABILITY_FREE else AVAILABILITY_BUSY
        v["uid2445"] = meta["uid"] as? String
        if (series != null) {
            val o = readTime(original) ?: return null
            v["original_sync_id"] = series
            v["originalInstanceTime"] = o.ms
            v["originalAllDay"] = if (o.date) 1 else 0
        }
        val reminders = reminders(meta["alerts"], s.ms, repeats)
        v["hasAlarm"] = if (reminders.isEmpty()) 0 else 1
        v["sync_data2"] = tag
        val fingerprint = Calendar.taggedHash("cc.aaro.calendar/row/1", CalJson.canon(mapOf("v" to v, "r" to reminders)).toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }.substring(0, 32)
        v["sync_data1"] = fingerprint
        return Row(entry, series, v, reminders, fingerprint)
    }

    private fun times(list: Any?): List<Long> = (list as? List<*>)?.mapNotNull { t ->
        readTime(t)?.ms
    }?.distinct()?.sorted() ?: emptyList()

    /** Alerts as minutes before the start: `before` (seconds) rounds down; `at` (unix) counts only on a single event. */
    private fun reminders(alerts: Any?, startMs: Long, repeats: Boolean): List<Int> = (alerts as? List<*>)?.mapNotNull { a ->
        val m = a as? Map<*, *> ?: return@mapNotNull null
        val before = (m["before"] as? Number)?.toLong()
        val at = (m["at"] as? Number)?.toLong()
        when {
            before != null && before >= 0 -> (before / 60).toInt()
            at != null && !repeats && startMs - at * 1000 >= 0 -> ((startMs - at * 1000) / 60000).toInt()
            else -> null
        }
    }?.distinct()?.sorted() ?: emptyList()
}
