// The shared calendar module, Kotlin copy: the event format's rules and the merge by field (KIST calendar profile §2,
// ~/kist proposals/calendar-profile.md). Gives the same bytes as calendar/js/calendar.js for the same input;
// calendar/vectors/calendar.json holds the cases both pass. Needs only the Kotlin and Java standard libraries.
//
// JSON values here are plain Kotlin: null, Boolean, Long, String, List<Any?>, Map<String, Any?>. An app turns its
// own JSON into these with CalJson.parse(text) and back with CalJson.canon(value).
//
// A version is a map {meta, data, deleted}: `meta` with `kind` and the fields, `data` the notes or null, `deleted`
// true for a deletion (then `meta` is {kind} only). Every field of `meta` except `kind` and `edited`, and `data`,
// carries a stamp in `meta.edited`: {"t": <ms>, "d": "<8 hex>"}. A field with no stamp has stamp 0.
package cc.aaro.calendar

import java.security.MessageDigest

/** JSON as plain Kotlin values, integers only (no floats), and RFC 8785 canonical output. */
object CalJson {
    const val MAX_SAFE = 9007199254740991L

    /** Parses JSON, refusing floats and integers past ±2^53. Objects keep the last of repeated keys, as JS does. */
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.space()
        val v = p.value()
        p.space()
        if (p.i != text.length) throw IllegalArgumentException("JSON: trailing text at ${p.i}")
        return v
    }

    /** Canonical JSON: keys sorted by UTF-16 code units, strings escaped as JSON.stringify does. */
    fun canon(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(v.toString())
            is String -> string(sb, v)
            is Int -> sb.append(v.toString())
            is Long -> { if (v > MAX_SAFE || v < -MAX_SAFE) throw IllegalArgumentException("not a safe integer"); sb.append(v.toString()) }
            is List<*> -> { sb.append('['); v.forEachIndexed { i, x -> if (i > 0) sb.append(','); write(sb, x) }; sb.append(']') }
            is Map<*, *> -> {
                sb.append('{')
                val keys = v.keys.map { it as? String ?: throw IllegalArgumentException("JSON keys are strings") }.sorted()
                keys.forEachIndexed { i, k -> if (i > 0) sb.append(','); string(sb, k); sb.append(':'); write(sb, v[k]) }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("not JSON: ${v::class}")
        }
    }

    private fun string(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000c' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> u(sb, c)
                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> { sb.append(c).append(s[i + 1]); i++ }
                c.isSurrogate() -> u(sb, c) // a lone surrogate, as JSON.stringify writes it
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    private fun u(sb: StringBuilder, c: Char) { sb.append("\\u").append(String.format("%04x", c.code)) }

    private class Parser(val s: String) {
        var i = 0
        fun fail(what: String): Nothing = throw IllegalArgumentException("JSON: $what at $i")
        fun space() { while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++ }
        fun value(): Any? {
            if (i >= s.length) fail("unexpected end")
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> word("true", true)
                'f' -> word("false", false)
                'n' -> word("null", null)
                else -> num()
            }
        }
        fun word(w: String, v: Any?): Any? { if (!s.startsWith(w, i)) fail("bad word"); i += w.length; return v }
        fun obj(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++; space()
            if (i < s.length && s[i] == '}') { i++; return m }
            while (true) {
                space(); if (i >= s.length || s[i] != '"') fail("expected a key")
                val k = str(); space()
                if (i >= s.length || s[i] != ':') fail("expected :"); i++; space()
                m.remove(k); m[k] = value(); space()
                if (i >= s.length) fail("unexpected end")
                if (s[i] == ',') { i++; continue }
                if (s[i] == '}') { i++; return m }
                fail("expected , or }")
            }
        }
        fun arr(): List<Any?> {
            val l = ArrayList<Any?>()
            i++; space()
            if (i < s.length && s[i] == ']') { i++; return l }
            while (true) {
                space(); l.add(value()); space()
                if (i >= s.length) fail("unexpected end")
                if (s[i] == ',') { i++; continue }
                if (s[i] == ']') { i++; return l }
                fail("expected , or ]")
            }
        }
        fun str(): String {
            val sb = StringBuilder()
            i++
            while (true) {
                if (i >= s.length) fail("unclosed string")
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) fail("bad escape")
                        when (val e = s[i++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000c'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) fail("bad \\u")
                                sb.append(s.substring(i, i + 4).toIntOrNull(16)?.toChar() ?: fail("bad \\u")); i += 4
                            }
                            else -> fail("bad escape \\$e")
                        }
                    }
                    c < ' ' -> fail("control character in a string")
                    else -> sb.append(c)
                }
            }
        }
        fun num(): Long {
            val start = i
            if (s[i] == '-') i++
            if (i >= s.length || !s[i].isDigit()) fail("bad number")
            if (s[i] == '0' && i + 1 < s.length && s[i + 1].isDigit()) fail("leading zero")
            while (i < s.length && s[i].isDigit()) i++
            if (i < s.length && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) fail("not an integer")
            val n = s.substring(start, i).toLongOrNull() ?: fail("number too big")
            if (n > MAX_SAFE || n < -MAX_SAFE) fail("number past 2^53")
            return n
        }
    }
}

/** Stamps, merges and entry ids for calendar entries (KIST calendar profile §2). */
object Calendar {
    /** The member of a version whose stamp is `edited.data`. */
    const val DATA = "data"
    private val UNSTAMPED = setOf("kind", "edited")
    private val DEVICE = Regex("^[0-9a-f]{8}$")

    data class Stamp(val t: Long, val d: String) : Comparable<Stamp> {
        override fun compareTo(other: Stamp): Int = if (t != other.t) t.compareTo(other.t) else d.compareTo(other.d)
        fun json(): Map<String, Any?> = mapOf("t" to t, "d" to d)
    }

    /** A stamp as written, or null when missing or malformed (a malformed stamp counts as no stamp). */
    fun readStamp(s: Any?): Stamp? {
        if (s !is Map<*, *>) return null
        val t = (s["t"] as? Number)?.toLong() ?: return null
        val d = s["d"] as? String ?: return null
        if (s["t"] !is Long && s["t"] !is Int) return null
        if (t < 0 || t > CalJson.MAX_SAFE || !DEVICE.matches(d)) return null
        return Stamp(t, d)
    }

    /** Orders stamps: `t`, then `d`; no stamp is below every stamp. */
    fun compareStamps(a: Any?, b: Any?): Int {
        val x = readStamp(a); val y = readStamp(b)
        if (x == null || y == null) return (if (x != null) 1 else 0) - (if (y != null) 1 else 0)
        return x.compareTo(y).coerceIn(-1, 1)
    }

    @Suppress("UNCHECKED_CAST")
    private fun meta(v: Map<String, Any?>): Map<String, Any?> = v["meta"] as Map<String, Any?>
    private fun stampOf(v: Map<String, Any?>, f: String): Stamp? = readStamp((meta(v)["edited"] as? Map<*, *>)?.get(f))
    private fun has(v: Map<String, Any?>, f: String) = if (f == DATA) v.containsKey(DATA) else meta(v).containsKey(f)
    private fun valueOf(v: Map<String, Any?>, f: String) = if (f == DATA) v[DATA] else meta(v)[f]
    private fun fieldsOf(v: Map<String, Any?>): Set<String> {
        val out = LinkedHashSet<String>()
        for (k in meta(v).keys) if (k !in UNSTAMPED) out.add(k)
        if (v.containsKey(DATA)) out.add(DATA)
        (meta(v)["edited"] as? Map<*, *>)?.keys?.forEach { if (it is String && it !in UNSTAMPED) out.add(it) }
        return out
    }
    private fun checkVersion(v: Map<String, Any?>) {
        val m = v["meta"] as? Map<*, *> ?: throw IllegalArgumentException("a version needs meta.kind")
        if (m["kind"] !is String) throw IllegalArgumentException("a version needs meta.kind")
        CalJson.canon(m); if (v.containsKey(DATA)) CalJson.canon(v[DATA])
    }

    /**
     * A new version stamped against the one it replaces (§2.4). `prev` is the version the edit was made on (null for
     * a new entry; a deletion counts as none), `next` is {meta, data} as the person left it (its `edited` is ignored).
     * Only fields whose value changed get a new stamp, `t` = max(clock, that field's t in `prev` + 1); a new entry
     * stamps every field it has. Other fields keep `prev`'s stamps.
     */
    fun stamp(prev: Map<String, Any?>?, next: Map<String, Any?>, clock: Long, device: String): Map<String, Any?> {
        if (clock < 0 || clock > CalJson.MAX_SAFE) throw IllegalArgumentException("clock must be whole milliseconds")
        if (!DEVICE.matches(device)) throw IllegalArgumentException("device must be 8 lowercase hex")
        checkVersion(next)
        val before0 = if (prev != null && prev["deleted"] == true) null else prev
        before0?.let { checkVersion(it) }
        // `data` is always there in a whole version: missing is null
        val n = mapOf("meta" to next["meta"], DATA to next[DATA])
        val p = before0?.let { mapOf("meta" to it["meta"], DATA to it[DATA]) }
        val edited = LinkedHashMap<String, Any?>()
        val fields = LinkedHashSet(fieldsOf(n)).apply { if (p != null) addAll(fieldsOf(p)) }
        for (f in fields) {
            val before = p?.let { stampOf(it, f) }
            if (p != null) {
                // unchanged, including a field neither has (one someone removed earlier): keeps its stamp
                val same = has(p, f) == has(n, f) && (!has(n, f) || CalJson.canon(valueOf(p, f)) == CalJson.canon(valueOf(n, f)))
                if (same) { if (before != null) edited[f] = before.json(); continue }
            } else if (!has(n, f)) continue
            edited[f] = Stamp(maxOf(clock, if (before != null) before.t + 1 else 0), device).json()
        }
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in meta(n)) if (k != "edited") m[k] = v
        m["edited"] = edited
        return linkedMapOf("meta" to m, DATA to n[DATA], "deleted" to false)
    }

    private class Candidate(val stamp: Stamp?, val present: Boolean, val value: Any?) {
        val text = if (present) CalJson.canon(value) else ""
        fun beats(b: Candidate): Boolean {
            val s = compareStamps(stamp?.json(), b.stamp?.json())
            if (s != 0) return s > 0
            if (present != b.present) return present
            return text > b.text
        }
    }

    /**
     * The merge of an entry's current versions (§2.4): each field takes the value with the highest stamp (`t`, then
     * `d`); at equal stamps a value beats no value, then the higher canonical JSON wins. `edited` is the per-field
     * maximum. An edit beats a delete: deletions count only when every version is one. The same versions in any
     * order give the same result, so every device writes the same bytes (CalJson.canon of the result).
     */
    fun merge(versions: List<Map<String, Any?>>): Map<String, Any?> {
        if (versions.isEmpty()) throw IllegalArgumentException("nothing to merge")
        versions.forEach { checkVersion(it) }
        val live = versions.filter { it["deleted"] != true }
        if (live.isEmpty()) {
            val kinds = versions.map { meta(it)["kind"] }.toSet()
            if (kinds.size != 1) throw IllegalArgumentException("versions of different kinds")
            return linkedMapOf("meta" to mapOf("kind" to kinds.first()), DATA to null, "deleted" to true)
        }
        val kinds = live.map { meta(it)["kind"] }.toSet()
        if (kinds.size != 1) throw IllegalArgumentException("versions of different kinds")
        val fields = sortedSetOf<String>().apply { live.forEach { addAll(fieldsOf(it)) } }
        val m = linkedMapOf<String, Any?>("kind" to kinds.first())
        val edited = LinkedHashMap<String, Any?>()
        var data: Any? = null
        for (f in fields) {
            var best: Candidate? = null
            for (v in live) {
                val c = Candidate(stampOf(v, f), has(v, f), valueOf(v, f))
                if (best == null || c.beats(best)) best = c
            }
            best!!
            best.stamp?.let { edited[f] = it.json() }
            if (!best.present) continue
            if (f == DATA) data = best.value else m[f] = best.value
        }
        m["edited"] = edited
        return linkedMapOf("meta" to m, DATA to data, "deleted" to false)
    }

    /**
     * What a changed instance shows (§2.2): the series' fields, then every field the instance gives that is not null,
     * with `rrule` null and `exdates`/`rdates` empty. `edited` is left out: this is for showing, not for merging.
     */
    fun instanceView(series: Map<String, Any?>, instance: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in series) if (k != "edited") out[k] = v
        for ((k, v) in instance) if (k != "edited" && v != null) out[k] = v
        out["kind"] = "instance"; out["rrule"] = null; out["exdates"] = emptyList<Any?>(); out["rdates"] = emptyList<Any?>()
        return out
    }

    // ── entry ids ──

    /** TH(tag, m) = SHA-256(utf8(tag) ‖ 0x00 ‖ m), as KIST §2. */
    fun taggedHash(tag: String, vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(tag.toByteArray(Charsets.UTF_8)); md.update(0)
        parts.forEach { md.update(it) }
        return md.digest()
    }

    private fun unhex(h: String, bytes: Int, what: String): ByteArray {
        if (h.length != bytes * 2 || h.any { it !in '0'..'9' && it !in 'a'..'f' }) throw IllegalArgumentException("$what must be $bytes bytes of lowercase hex")
        return ByteArray(bytes) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun id32(tag: String, vararg parts: ByteArray) = taggedHash(tag, *parts).joinToString("") { "%02x".format(it) }.substring(0, 32)
    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

    /** A changed instance's entry id: TH("nostr-vault/instance/1", series entry ‖ utf8(canon(original))). */
    fun instanceId(seriesEntry: String, original: Any?): String =
        id32("nostr-vault/instance/1", unhex(seriesEntry, 16, "series entry"), utf8(CalJson.canon(original)))

    /** An imported event's entry id: TH("nostr-vault/cal-import/1", vault id ‖ utf8(uid)). */
    fun importId(vaultId: String, uid: String): String = id32("nostr-vault/cal-import/1", unhex(vaultId, 32, "vault id"), utf8(uid))

    /** A calendar vault's settings entry id: TH("nostr-vault/cal-settings/1", vault id). */
    fun settingsId(vaultId: String): String = id32("nostr-vault/cal-settings/1", unhex(vaultId, 32, "vault id"))
}
