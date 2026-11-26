package cc.aaro.calendar

import cc.aaro.calendar.CalendarRows.Dirty
import cc.aaro.calendar.CalendarRows.Existing
import cc.aaro.calendar.CalendarRows.Op
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CalendarRowsTest {
    private val series = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
    private val single = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
    private fun at(local: String, tz: String = "America/Denver") = mapOf("local" to local, "tz" to tz)
    private fun v(meta: Map<String, Any?>, data: Any? = null, deleted: Boolean = false) = mapOf("meta" to meta, "data" to data, "deleted" to deleted)
    private val dentist = v(mapOf("kind" to "event", "uid" to "dentist@kist", "title" to "Dentist", "start" to at("2026-12-01T09:30:00"),
        "end" to at("2026-12-01T10:30:00"), "location" to "Main St", "status" to "confirmed", "busy" to true,
        "alerts" to listOf(mapOf("before" to 900L), mapOf("at" to 1796142600L - 3600)), "edited" to emptyMap<String, Any?>()), mapOf("text" to "Bring the form"))
    private val standup = v(mapOf("kind" to "event", "title" to "Standup", "start" to at("2026-12-01T09:30:00"), "end" to at("2026-12-01T09:45:00"),
        "rrule" to "FREQ=WEEKLY;BYDAY=TU", "exdates" to listOf(at("2026-12-15T09:30:00")), "alerts" to listOf(mapOf("before" to 600L), mapOf("at" to 1L))))
    private val moved = v(mapOf("kind" to "instance", "series" to series, "original" to at("2026-12-08T09:30:00"), "start" to at("2026-12-08T10:00:00"),
        "end" to at("2026-12-08T10:15:00"), "title" to null))

    @Test fun aSingleEvent() {
        val (rows, skipped) = CalendarRows.rows(mapOf(single to dentist), mapOf(single to "ver1"))
        assertTrue(skipped.isEmpty())
        val r = rows.single().values
        assertEquals(single, r["_sync_id"])
        assertEquals(1796142600000L, r["dtstart"]) // 09:30 MST = 16:30 UTC
        assertEquals(1796146200000L, r["dtend"])
        assertEquals("America/Denver", r["eventTimezone"])
        assertNull(r["duration"]); assertNull(r["rrule"])
        assertEquals("Bring the form", r["description"])
        assertEquals(CalendarRows.STATUS_CONFIRMED, r["eventStatus"])
        assertEquals(CalendarRows.AVAILABILITY_BUSY, r["availability"])
        assertEquals("dentist@kist", r["uid2445"])
        assertEquals("ver1", r["sync_data2"])
        assertEquals(listOf(15, 60), rows.single().reminders)
        assertEquals(1, r["hasAlarm"])
    }

    @Test fun aSeriesAndAMovedTuesday() {
        val (rows, _) = CalendarRows.rows(mapOf(series to standup, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1" to moved))
        val s = rows.first { it.series == null }.values
        assertNull(s["dtend"]); assertEquals("P900S", s["duration"])
        assertEquals("FREQ=WEEKLY;BYDAY=TU", s["rrule"])
        assertEquals("20261215T163000Z", s["exdate"])
        assertEquals(listOf(10), rows.first { it.series == null }.reminders) // an `at` alert does not repeat
        val i = rows.first { it.series != null }.values
        assertEquals(series, i["original_sync_id"])
        assertEquals(1796747400000L, i["originalInstanceTime"])
        assertEquals("Standup", i["title"]) // null falls back to the series
        assertNull(i["rrule"]); assertEquals(1796749200000L, i["dtstart"]); assertEquals(1796750100000L, i["dtend"])
    }

    @Test fun allDayAndFreeRange() {
        val trip = v(mapOf("kind" to "event", "title" to "Away", "start" to mapOf("date" to "2026-12-24"), "end" to mapOf("date" to "2026-12-27"), "all_day" to true))
        val free = v(mapOf("kind" to "event", "start" to at("2026-12-05T18:00:00"), "busy" to false))
        val (rows, _) = CalendarRows.rows(mapOf("01" to trip, "02" to free))
        val t = rows.first { it.entry == "01" }.values
        assertEquals(1, t["allDay"]); assertEquals("UTC", t["eventTimezone"])
        assertEquals(1798070400000L, t["dtstart"]); assertEquals(1798329600000L, t["dtend"])
        val f = rows.first { it.entry == "02" }.values
        assertEquals(CalendarRows.AVAILABILITY_FREE, f["availability"]); assertEquals(f["dtstart"], f["dtend"])
    }

    @Test fun deletedOrseriesless() {
        val (rows, skipped) = CalendarRows.rows(mapOf(single to v(mapOf("kind" to "event"), deleted = true), "b1" to moved,
            "c1" to v(mapOf("kind" to "settings", "color" to "#fff")), "d1" to v(mapOf("kind" to "event", "title" to "no start"))))
        assertTrue(rows.isEmpty())
        assertEquals(listOf("b1", "d1"), skipped.sorted())
    }

    @Test fun planning() {
        val (rows, _) = CalendarRows.rows(mapOf(series to standup, "b1" to moved, single to dentist))
        val fp = rows.associate { it.entry to it.fingerprint }
        // nothing there yet: series and single first, the instance last
        val p0 = CalendarRows.plan(rows, emptyList())
        assertEquals(listOf(series, single, "b1"), p0.ops.map { (it as Op.Insert).row.entry }.let { listOf(it[0], it[1], it[2]) }.sortedBy { if (it == "b1") 1 else 0 })
        assertTrue(p0.ops.last() is Op.Insert && (p0.ops.last() as Op.Insert).row.series == series)
        // all there and right: nothing to do
        val there = listOf(Existing(1, series, fp[series], false, false), Existing(2, "b1", fp["b1"], false, false), Existing(3, single, fp[single], false, false))
        assertTrue(CalendarRows.plan(rows, there).ops.isEmpty())
        // one changed, one gone, one stray, one duplicate
        val changed = there.map { if (it.entry == single) it.copy(fingerprint = "old") else it } + Existing(9, "zz", "x", false, false) + Existing(10, series, fp[series], false, false)
        val p1 = CalendarRows.plan(rows.filter { it.entry != "b1" }, changed)
        assertEquals(setOf(2L, 9L, 10L), p1.ops.filterIsInstance<Op.Delete>().map { it.id }.toSet())
        assertEquals(listOf(3L), p1.ops.filterIsInstance<Op.Update>().map { it.id })
        assertTrue(p1.ops.take(3).all { it is Op.Delete })
        // only the entries named
        val p2 = CalendarRows.plan(rows.filter { it.entry != "b1" }, changed, only = setOf(single))
        assertEquals(listOf(Op.Update(3, rows.first { it.entry == single })), p2.ops)
        // a row changed in the phone is held, not written over, and not removed
        val dirty = there.map { if (it.entry == single) it.copy(fingerprint = "old", dirty = true) else it }
        val p3 = CalendarRows.plan(rows.filter { it.entry != single }, dirty)
        assertTrue(p3.ops.isEmpty()); assertEquals(listOf(single), p3.held)
        val p4 = CalendarRows.plan(rows, dirty, dirty = Dirty.OVERWRITE)
        assertEquals(listOf(Op.Update(3, rows.first { it.entry == single })), p4.ops)
    }

    @Test fun anUnknownZoneKeepsTheEvent() {
        val (rows, _) = CalendarRows.rows(mapOf("01" to v(mapOf("kind" to "event", "start" to at("2026-12-01T09:30:00", "Custom/Nowhere")))))
        assertEquals("UTC", rows.single().values["eventTimezone"])
        assertEquals(1796117400000L, rows.single().values["dtstart"])
    }
}
