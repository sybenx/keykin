// The shared calendar module, Android part: writes calendar entries into the phone's own calendar
// (CalendarContract), one calendar per source ("DMs plans", one per Marble calendar vault), each event row keyed by
// its entry id, and keeps the rows following the entries as their merged versions change. What goes in a row and
// which rows change is CalendarRows (pure Kotlin, ../kotlin); this file only reads and writes the provider.
//
// It writes as a sync adapter for an account: Marble passes its own calendar account; an app with no account of
// its own (DMs "Add to my calendar") uses ACCOUNT_TYPE_LOCAL, which Android allows without an authenticator.
// Needs READ_CALENDAR and WRITE_CALENDAR.
//
// Reading back edits made in the phone's calendar app is the next half. The seam: rows the calendar app changed are
// marked dirty by Android; `sync` holds them (never writes over them) and `changedInPhone` lists them with the
// tag (sync_data2) of the version each row showed, which is what that half compares against.
package cc.aaro.calendar

import android.content.ContentProviderOperation
import android.content.ContentResolver
import android.content.ContentValues
import android.net.Uri
import android.provider.CalendarContract
import android.provider.CalendarContract.Calendars
import android.provider.CalendarContract.Events
import android.provider.CalendarContract.Reminders

class AndroidCalendar(
    private val resolver: ContentResolver,
    private val accountName: String,
    private val accountType: String = CalendarContract.ACCOUNT_TYPE_LOCAL,
) {
    /**
     * One calendar in the phone. `key` names it for good (a vault id, "dms-plans"); `name` and `color` may change.
     * `access` is CalendarContract's access level: READ (200, the default) until edits made in the phone can be
     * read back, so nothing typed there is lost; OWNER (700) once they can.
     */
    data class Source(val key: String, val name: String, val color: Int, val tz: String = "UTC", val access: Int = Calendars.CAL_ACCESS_READ)

    data class Result(val calendarId: Long, val inserted: Int, val updated: Int, val deleted: Int, val held: List<String>, val skipped: List<String>)

    /** A row the calendar app changed (or deleted) since we wrote it. `tag`: what we wrote it from. */
    data class Changed(val rowId: Long, val entry: String?, val tag: String?, val deleted: Boolean)

    private fun Uri.asAdapter(): Uri = buildUpon()
        .appendQueryParameter(CalendarContract.CALLER_IS_SYNCADAPTER, "true")
        .appendQueryParameter(Calendars.ACCOUNT_NAME, accountName)
        .appendQueryParameter(Calendars.ACCOUNT_TYPE, accountType)
        .build()

    /** The calendar's row id, or null if it isn't in the phone. */
    fun calendarId(key: String): Long? = resolver.query(
        Calendars.CONTENT_URI.asAdapter(), arrayOf(Calendars._ID),
        "${Calendars.ACCOUNT_NAME}=? AND ${Calendars.ACCOUNT_TYPE}=? AND ${Calendars._SYNC_ID}=?",
        arrayOf(accountName, accountType, key), "${Calendars._ID} ASC",
    )?.use { if (it.moveToFirst()) it.getLong(0) else null }

    /** Adds the calendar, or brings its name, color and access up to date. Returns its row id. */
    fun ensureCalendar(source: Source): Long {
        val v = ContentValues().apply {
            put(Calendars.NAME, source.name)
            put(Calendars.CALENDAR_DISPLAY_NAME, source.name)
            put(Calendars.CALENDAR_COLOR, source.color)
            put(Calendars.CALENDAR_ACCESS_LEVEL, source.access)
            put(Calendars.CALENDAR_TIME_ZONE, source.tz)
            put(Calendars.VISIBLE, 1)
            put(Calendars.SYNC_EVENTS, 1)
        }
        calendarId(source.key)?.let { id ->
            resolver.update(Calendars.CONTENT_URI.asAdapter(), v, "${Calendars._ID}=?", arrayOf(id.toString()))
            return id
        }
        v.put(Calendars.ACCOUNT_NAME, accountName)
        v.put(Calendars.ACCOUNT_TYPE, accountType)
        v.put(Calendars.OWNER_ACCOUNT, accountName)
        v.put(Calendars._SYNC_ID, source.key)
        val uri = resolver.insert(Calendars.CONTENT_URI.asAdapter(), v) ?: error("the calendar provider refused the calendar")
        return uri.lastPathSegment!!.toLong()
    }

    /** Takes the calendar and every row in it out of the phone. */
    fun removeCalendar(key: String): Boolean {
        val id = calendarId(key) ?: return false
        return resolver.delete(Calendars.CONTENT_URI.asAdapter(), "${Calendars._ID}=?", arrayOf(id.toString())) > 0
    }

    /**
     * Makes the calendar show `entries` (entry id → current merged version). With `only`, just those entries are
     * looked at (an app sending what changed: a removed one is passed as a deletion or left out of `entries`);
     * without, every other row in the calendar is removed. Running it again with the same entries changes nothing.
     */
    fun sync(
        source: Source,
        entries: Map<String, Map<String, Any?>>,
        tags: Map<String, String> = emptyMap(),
        only: Set<String>? = null,
        dirty: CalendarRows.Dirty = CalendarRows.Dirty.HOLD,
    ): Result {
        val cal = ensureCalendar(source)
        val (rows, skipped) = CalendarRows.rows(entries, tags)
        val plan = CalendarRows.plan(rows, existing(cal), only, dirty, skipped)
        val ops = ArrayList<ContentProviderOperation>()
        var ins = 0; var upd = 0; var del = 0
        for (op in plan.ops) when (op) {
            is CalendarRows.Op.Delete -> {
                ops += ContentProviderOperation.newDelete(Events.CONTENT_URI.asAdapter())
                    .withSelection("${Events._ID}=?", arrayOf(op.id.toString())).build()
                del++
            }
            is CalendarRows.Op.Insert -> {
                val at = ops.size
                ops += ContentProviderOperation.newInsert(Events.CONTENT_URI.asAdapter())
                    .withValues(values(op.row).apply { put(Events.CALENDAR_ID, cal) }).build()
                for (m in op.row.reminders) ops += ContentProviderOperation.newInsert(Reminders.CONTENT_URI.asAdapter())
                    .withValueBackReference(Reminders.EVENT_ID, at)
                    .withValue(Reminders.MINUTES, m).withValue(Reminders.METHOD, Reminders.METHOD_ALERT).build()
                ins++
            }
            is CalendarRows.Op.Update -> {
                ops += ContentProviderOperation.newUpdate(Events.CONTENT_URI.asAdapter())
                    .withSelection("${Events._ID}=?", arrayOf(op.id.toString()))
                    .withValues(values(op.row).apply { put(Events.DIRTY, 0) }).build()
                ops += ContentProviderOperation.newDelete(Reminders.CONTENT_URI.asAdapter())
                    .withSelection("${Reminders.EVENT_ID}=?", arrayOf(op.id.toString())).build()
                for (m in op.row.reminders) ops += ContentProviderOperation.newInsert(Reminders.CONTENT_URI.asAdapter())
                    .withValue(Reminders.EVENT_ID, op.id)
                    .withValue(Reminders.MINUTES, m).withValue(Reminders.METHOD, Reminders.METHOD_ALERT).build()
                upd++
            }
        }
        if (ops.isNotEmpty()) resolver.applyBatch(CalendarContract.AUTHORITY, ops)
        return Result(cal, ins, upd, del, plan.held, plan.skipped)
    }

    /** Rows the phone's calendar app changed or deleted since we wrote them: the seam for reading edits back. */
    fun changedInPhone(key: String): List<Changed> {
        val cal = calendarId(key) ?: return emptyList()
        return resolver.query(
            Events.CONTENT_URI.asAdapter(), arrayOf(Events._ID, Events._SYNC_ID, Events.SYNC_DATA2, Events.DELETED),
            "${Events.CALENDAR_ID}=? AND ${Events.DIRTY}=1", arrayOf(cal.toString()), "${Events._ID} ASC",
        )?.use { c ->
            buildList { while (c.moveToNext()) add(Changed(c.getLong(0), c.getString(1), c.getString(2), c.getInt(3) == 1)) }
        } ?: emptyList()
    }

    /** Every row of the calendar, as CalendarRows plans against. */
    private fun existing(cal: Long): List<CalendarRows.Existing> = resolver.query(
        Events.CONTENT_URI.asAdapter(), arrayOf(Events._ID, Events._SYNC_ID, Events.SYNC_DATA1, Events.DIRTY, Events.DELETED),
        "${Events.CALENDAR_ID}=?", arrayOf(cal.toString()), "${Events._ID} ASC",
    )?.use { c ->
        buildList { while (c.moveToNext()) add(CalendarRows.Existing(c.getLong(0), c.getString(1), c.getString(2), c.getInt(3) == 1, c.getInt(4) == 1)) }
    } ?: emptyList()

    private fun values(row: CalendarRows.Row) = ContentValues().apply {
        for ((k, v) in row.values) when (v) {
            null -> putNull(k)
            is Int -> put(k, v)
            is Long -> put(k, v)
            is String -> put(k, v)
            else -> put(k, v.toString())
        }
    }
}
