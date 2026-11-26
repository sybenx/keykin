package cc.aaro.calendar

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

@Suppress("UNCHECKED_CAST")
class CalendarVectorsTest {
    private val v = CalJson.parse(File(System.getProperty("calendar.vectors")).readText()) as Map<String, Any?>
    private fun cases(k: String) = v[k] as List<Map<String, Any?>>
    private fun obj(x: Any?) = x as Map<String, Any?>
    private val canon = CalJson::canon

    @Test fun stamping() {
        for (c in cases("stamp")) {
            val got = Calendar.stamp(c["prev"]?.let(::obj), obj(c["next"]), c["clock"] as Long, c["device"] as String)
            assertEquals(c["name"] as String, canon(c["expect"]), canon(got))
        }
    }

    @Test fun merging() {
        for (c in cases("merge")) {
            val name = c["name"] as String
            val vs = (c["versions"] as List<Any?>).map(::obj)
            val want = c["canon"] as String
            for (r in vs.indices) {
                val turned = vs.drop(r) + vs.take(r)
                assertEquals("$name, turned $r", want, canon(Calendar.merge(turned)))
                assertEquals("$name, reversed $r", want, canon(Calendar.merge(turned.reversed())))
            }
            assertEquals(name, want, canon(c["expect"]))
            assertEquals("$name: merge of the merge", want, canon(Calendar.merge(listOf(obj(c["expect"])))))
            for (x in vs) assertEquals("$name: merge with an input", want, canon(Calendar.merge(listOf(obj(c["expect"]), x))))
        }
    }

    @Test fun viewsCanonAndIds() {
        for (c in cases("instance_view")) assertEquals(c["name"] as String, canon(c["expect"]), canon(Calendar.instanceView(obj(c["series"]), obj(c["instance"]))))
        for (c in cases("canon")) assertEquals(c["expect"], canon(c["value"]))
        for (c in cases("ids")) {
            val got = when (c["fn"]) {
                "instance" -> Calendar.instanceId(c["series"] as String, c["original"])
                "import" -> Calendar.importId(c["vault"] as String, c["uid"] as String)
                else -> Calendar.settingsId(c["vault"] as String)
            }
            assertEquals(canon(c), c["expect"], got)
        }
    }

    @Test fun refuses() {
        assertThrows(IllegalArgumentException::class.java) { Calendar.merge(emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { CalJson.parse("{\"n\":1.5}") }
        assertThrows(IllegalArgumentException::class.java) { CalJson.parse("9007199254740992") }
        assertThrows(IllegalArgumentException::class.java) {
            Calendar.merge(listOf(mapOf("meta" to mapOf("kind" to "event")), mapOf("meta" to mapOf("kind" to "settings"))))
        }
        assertThrows(IllegalArgumentException::class.java) { Calendar.stamp(null, mapOf("meta" to mapOf("kind" to "event")), 1, "A1B2C3D4") }
        assertThrows(IllegalArgumentException::class.java) { Calendar.instanceId("ab", mapOf("date" to "2026-12-01")) }
    }
}
