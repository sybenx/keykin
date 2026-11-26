package cc.aaro.calendar

import android.Manifest
import android.content.ContentUris
import android.content.ContentValues
import android.provider.CalendarContract.Events
import android.provider.CalendarContract.Instances
import android.provider.CalendarContract.Reminders
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidCalendarTest {
    @get:Rule val perms: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.READ_CALENDAR, Manifest.permission.WRITE_CALENDAR)

    private val resolver = InstrumentationRegistry.getInstrumentation().targetContext.contentResolver
    private val cal = AndroidCalendar(resolver, "calendar-module-test")
    private val source = AndroidCalendar.Source("test-" + System.nanoTime(), "DMs plans", 0xFF3B82F6.toInt(), "America/Denver")

    private val series = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
    private val single = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
    private val moved = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
    private fun at(local: String) = mapOf("local" to local, "tz" to "America/Denver")
    private fun v(meta: Map<String, Any?>, data: Any? = null, deleted: Boolean = false) = mapOf("meta" to meta, "data" to data, "deleted" to deleted)
    private fun dentist(title: String) = v(mapOf("kind" to "event", "uid" to "dentist@kist", "title" to title, "start" to at("2026-12-01T09:30:00"),
        "end" to at("2026-12-01T10:30:00"), "location" to "Main St", "status" to "confirmed", "alerts" to listOf(mapOf("before" to 900L), mapOf("before" to 3600L))),
        mapOf("text" to "Bring the form"))
    private val standup = v(mapOf("kind" to "event", "title" to "Standup", "start" to at("2026-12-01T09:30:00"), "end" to at("2026-12-01T09:45:00"),
        "rrule" to "FREQ=WEEKLY;BYDAY=TU", "exdates" to listOf(at("2026-12-15T09:30:00"))))
    private val tuesday = v(mapOf("kind" to "instance", "series" to series, "original" to at("2026-12-08T09:30:00"),
        "start" to at("2026-12-08T10:00:00"), "end" to at("2026-12-08T10:15:00")))
    private val all = mapOf(single to dentist("Dentist"), series to standup, moved to tuesday)

    @After fun cleanUp() { cal.removeCalendar(source.key) }

    private fun row(entry: String): Map<String, Any?>? {
        val id = cal.calendarId(source.key)!!
        return resolver.query(Events.CONTENT_URI, arrayOf(Events._ID, Events.TITLE, Events.DTSTART, Events.DTEND, Events.DURATION, Events.EVENT_TIMEZONE,
            Events.RRULE, Events.EXDATE, Events.EVENT_LOCATION, Events.DESCRIPTION, Events.ORIGINAL_ID, Events.UID_2445, Events.HAS_ALARM),
            "${Events.CALENDAR_ID}=? AND ${Events._SYNC_ID}=?", arrayOf(id.toString(), entry), null)!!.use { c ->
            if (!c.moveToFirst()) null else (0 until c.columnCount).associate { c.getColumnName(it) to if (c.isNull(it)) null else c.getString(it) }
        }
    }
    private fun reminders(rowId: String) = resolver.query(Reminders.CONTENT_URI, arrayOf(Reminders.MINUTES), "${Reminders.EVENT_ID}=?", arrayOf(rowId), "${Reminders.MINUTES} ASC")!!
        .use { c -> buildList { while (c.moveToNext()) add(c.getInt(0)) } }
    /** What the phone's calendar shows for December: [title, start ms]. */
    private fun december(): List<Pair<String?, Long>> {
        val b = Instances.CONTENT_URI.buildUpon()
        ContentUris.appendId(b, 1796083200000L); ContentUris.appendId(b, 1798761600000L)
        return resolver.query(b.build(), arrayOf(Instances.TITLE, Instances.BEGIN), "${Instances.CALENDAR_ID}=?", arrayOf(cal.calendarId(source.key)!!.toString()), "${Instances.BEGIN} ASC")!!
            .use { c -> buildList { while (c.moveToNext()) add(c.getString(0) to c.getLong(1)) } }
    }

    @Test fun writesFollowsAndRemoves() {
        val r1 = cal.sync(source, all)
        assertEquals(3, r1.inserted)
        val d = row(single)!!
        assertEquals("Dentist", d["title"]); assertEquals("1796142600000", d["dtstart"]); assertEquals("1796146200000", d["dtend"])
        assertEquals("America/Denver", d["eventTimezone"]); assertEquals("Main St", d["eventLocation"]); assertEquals("Bring the form", d["description"])
        assertEquals("dentist@kist", d["uid2445"]); assertEquals(listOf(15, 60), reminders(d["_id"] as String))
        val s = row(series)!!
        assertEquals("FREQ=WEEKLY;BYDAY=TU", s["rrule"]); assertEquals("P900S", s["duration"]); assertNull(s["dtend"])
        assertEquals(s["_id"], row(moved)!!["original_id"]) // the changed Tuesday is tied to its series

        // December as the calendar app shows it: the dentist, Standup on 1, 8 (moved to 10:00), 22 and 29; not 15
        val dec = december()
        assertEquals(listOf(1796142600000L, 1796142600000L, 1796749200000L, 1797957000000L, 1798561800000L), dec.map { it.second })
        assertTrue(dec.any { it == "Standup" to 1796749200000L })

        // the same again: nothing to write
        val r2 = cal.sync(source, all)
        assertEquals(listOf(0, 0, 0), listOf(r2.inserted, r2.updated, r2.deleted))

        // a later change follows
        val r3 = cal.sync(source, all + (single to dentist("Dentist, Dr Lee")))
        assertEquals(1, r3.updated); assertEquals("Dentist, Dr Lee", row(single)!!["title"])
        assertEquals(listOf(15, 60), reminders(row(single)!!["_id"] as String))

        // just one entry named: the others are left alone
        val r4 = cal.sync(source, mapOf(single to v(mapOf("kind" to "event"), deleted = true)), only = setOf(single))
        assertEquals(1, r4.deleted); assertNull(row(single)); assertTrue(row(series) != null)

        // the series removed: its changed Tuesday goes too
        cal.sync(source, emptyMap())
        assertNull(row(series)); assertNull(row(moved)); assertTrue(december().isEmpty())
    }

    @Test fun anEditInThePhoneIsHeld() {
        cal.sync(source, all)
        val id = row(single)!!["_id"] as String
        // the calendar app changing the title (not as the sync adapter, so Android marks it dirty)
        resolver.update(ContentUris.withAppendedId(Events.CONTENT_URI, id.toLong()), ContentValues().apply { put(Events.TITLE, "Typed on the phone") }, null, null)
        val changed = cal.changedInPhone(source.key)
        assertEquals(listOf(single), changed.map { it.entry })
        val r = cal.sync(source, all + (single to dentist("From another device")))
        assertEquals(listOf(single), r.held)
        assertEquals("Typed on the phone", row(single)!!["title"])
        // once read back, the app may write over it
        cal.sync(source, all + (single to dentist("Merged")), dirty = CalendarRows.Dirty.OVERWRITE)
        assertEquals("Merged", row(single)!!["title"]); assertTrue(cal.changedInPhone(source.key).isEmpty())
    }

    @Test fun calendarNameAndColorFollow() {
        val first = cal.ensureCalendar(source)
        assertEquals(first, cal.ensureCalendar(source.copy(name = "Plans", color = 0xFFEF4444.toInt())))
        assertTrue(cal.removeCalendar(source.key)); assertNull(cal.calendarId(source.key))
    }
}
