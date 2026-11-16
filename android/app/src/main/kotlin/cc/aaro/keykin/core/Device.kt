// A device's side of everything (SPEC §2 to §8b). `Me` is this device: its member key and, if it has
// one, its chip. `send` carries a signed request to the box and returns the reply.
package cc.aaro.keykin.core

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL

/** Signs `message` with the chip key after a fingerprint, and returns the signature as 64 bytes hex (r ‖ s). */
typealias Fingerprint = (message: ByteArray) -> String
typealias Send = (JSONObject) -> JSONObject

class Me(val sk: ByteArray, val name: String, val chip: String?) { val key: String = Secp.pub(sk) }
/** What a device keeps once it is in an account. */
/** `piece` and `epoch` change when the keys are cycled; `changed` is told, so the app can save. */
class Held(var piece: Piece, val npub: String, val boxKey: String, val addr: String, var epoch: Int = 0) {
    var changed: (Held) -> Unit = {}
    fun json(): JSONObject = JSONObject().put("commitment", JSONArray(piece.c)).put("i", piece.i).put("share", scalarHex(piece.share)).put("npub", npub).put("boxKey", boxKey).put("addr", addr).put("epoch", epoch)
    override fun equals(other: Any?) = other is Held && other.json().toString() == json().toString()
    override fun hashCode() = json().toString().hashCode()
    companion object {
        fun of(o: JSONObject) = Held(Piece(o.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }, o.getInt("i"), BigInteger(o.getString("share"), 16)), o.getString("npub"), o.getString("boxKey"), o.getString("addr"), o.optInt("epoch", 0))
    }
}
data class Member(val key: String, val i: Int, val name: String, val kind: String, val chip: Boolean, val blocked: Boolean, val added: Long)
data class Qr(val addr: String, val key: String, val code: String)
data class Invite(val key: String, val name: String, val chip: String?)
data class JoinText(val addr: String, val boxKey: String, val npub: String)

object Texts {
    private val KEY = Regex("^[0-9a-f]{64}$")
    fun qr(text: String): Qr = try {
        val q = JSONObject(text)
        if (q.optInt("keykin") != 2 || !KEY.matches(q.getString("key"))) refuse("bad_qr")
        Qr(q.getString("addr"), q.getString("key"), q.getString("code"))
    } catch (e: KeykinException) { throw e } catch (_: Exception) { refuse("bad_qr") }
    fun invite(me: Me): String = JSONObject().put("keykin", 2).put("invite", JSONObject().put("key", me.key).put("name", me.name).apply { if (me.chip != null) put("chip", me.chip) }).toString()
    fun readInvite(text: String): Invite = try {
        val i = JSONObject(text).getJSONObject("invite")
        if (!KEY.matches(i.getString("key"))) refuse("bad_invite")
        Invite(i.getString("key"), i.getString("name"), if (i.has("chip")) i.getString("chip") else null)
    } catch (e: KeykinException) { throw e } catch (_: Exception) { refuse("bad_invite") }
    fun join(h: Held): String = JSONObject().put("keykin", 2).put("join", JSONObject().put("addr", h.addr).put("boxKey", h.boxKey).put("npub", h.npub)).toString()
    fun readJoin(text: String): JoinText = try {
        val j = JSONObject(text).getJSONObject("join")
        if (!KEY.matches(j.getString("boxKey")) || !KEY.matches(j.getString("npub"))) refuse("bad_join")
        JoinText(j.getString("addr"), j.getString("boxKey"), j.getString("npub"))
    } catch (e: KeykinException) { throw e } catch (_: Exception) { refuse("bad_join") }
}

object Device {
    private fun now() = System.currentTimeMillis() / 1000

    /** A signed request: `{ body, key, sig }`, plus `fp` when a fingerprint signs it too (SPEC §4). */
    fun seal(body: JSONObject, me: Me, fp: Fingerprint? = null): JSONObject {
        body.put("ts", now()).put("id", hex(random(16)))
        val bytes = utf8(jcs(body))
        val out = JSONObject().put("body", body).put("key", me.key).put("sig", Secp.schnorrSign(sha256(bytes), me.sk))
        if (fp != null) out.put("fp", fp(bytes))
        return out
    }
    private fun call(send: Send, req: JSONObject): JSONObject = send(req).also { if (it.has("error")) refuse(it.getString("error")) }

    /**
     * A request that depends on the current pieces. If the keys were cycled while this device was away, the
     * box says `stale` and hands over the changes; the device applies them and asks again.
     */
    private fun current(me: Me, h: Held, send: Send, fp: Fingerprint? = null, body: () -> JSONObject): JSONObject {
        var tries = 0
        while (true) {
            val r = send(seal(body().put("epoch", h.epoch), me, fp))
            if (r.optString("error") != "stale" || tries++ > 0) { if (r.has("error")) refuse(r.getString("error")); return r }
            var share = h.piece.share
            val cs = r.getJSONArray("catchups")
            for (k in 0 until cs.length()) cs.getJSONObject(k).let { c -> share = share.add(BigInteger(Seal.from(me.sk, c.getString("from"), "cycle", c.getString("sealed")), 16)).mod(N) }
            val c = r.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }
            adopt(h, c, share, r.getInt("epoch"))
            call(send, seal(JSONObject().put("op", "caught_up"), me))
        }
    }
    /** Takes a new piece only if it lies on the new line of the same key: share·G = C0 + i·C1. */
    private fun adopt(h: Held, c: List<String>, share: BigInteger, epoch: Int) {
        if (c.size != 2 || c[0].substring(2) != h.npub) refuse("bad_piece")
        if (Secp.mulG(share) != Secp.add(c[0], Secp.mul(BigInteger.valueOf(h.piece.i.toLong()), c[1]))) refuse("bad_piece")
        h.piece = Piece(c, h.piece.i, share); h.epoch = epoch; h.changed(h)
    }

    /** Talks to a box over HTTP. */
    fun http(addr: String): Send = { req ->
        val c = URL("$addr/keykin").openConnection() as HttpURLConnection
        try {
            c.requestMethod = "POST"; c.doOutput = true; c.connectTimeout = 8000; c.readTimeout = 15000
            c.setRequestProperty("content-type", "application/json")
            c.outputStream.use { it.write(utf8(req.toString())) }
            JSONObject(String((if (c.responseCode < 400) c.inputStream else c.errorStream).readBytes(), Charsets.UTF_8))
        } catch (e: java.io.IOException) { refuse("no_box", e.message) } finally { c.disconnect() }
    }

    /** After scanning the box's QR: the device and the box make the key together. No whole key exists. */
    fun create(me: Me, qr: Qr, send: Send = http(qr.addr)): Held {
        val one = Frost.dkg1(1)
        val r1 = call(send, seal(JSONObject().put("op", "create1").put("code", qr.code).put("pkg", one.pkg).put("name", me.name).apply { if (me.chip != null) put("chip", me.chip) }, me))
        val box = listOf(2 to r1.getString("pkg"))
        val two = Frost.dkg2(one.secret, box)
        val r2 = call(send, seal(JSONObject().put("op", "create2").put("pkg2", Seal.to(me.sk, qr.key, "keygen", two.pkgFor[2] ?: refuse("bad_keygen"))), me))
        val done = Frost.dkg3(two.secret, box, listOf(2 to Seal.from(me.sk, qr.key, "keygen", r2.getString("pkg2"))))
        if (done.npub != r2.getString("npub")) refuse("bad_keygen")
        return Held(Piece(done.c, 1, done.share), done.npub, qr.key, qr.addr)
    }

    /** Signs a Nostr event with the box. Returns the whole signed event. */
    fun sign(me: Me, h: Held, kind: Int, content: String, tags: List<List<String>> = emptyList(), createdAt: Long = now(), send: Send = http(h.addr)): JSONObject {
        val id = eventId(h.npub, createdAt, kind, tags, content)
        val ev = JSONObject().put("pubkey", h.npub).put("created_at", createdAt).put("kind", kind).put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content)
        lateinit var mine: Frost.Asked
        val r = current(me, h, send) { mine = Frost.ask(h.piece, id); JSONObject().put("op", "sign").put("event", ev).put("commit", mine.commit.json()) }
        if (r.getString("id") != id) refuse("wrong_id")
        val c = r.getJSONObject("commit")
        return ev.put("id", id).put("sig", Frost.finish(h.piece, id, mine, Commit(c.getInt("i"), c.getString("D"), c.getString("E")), r.getString("z")))
    }

    fun members(me: Me, h: Held, send: Send = http(h.addr)): List<Member> = listing(me, send).first
    private fun listing(me: Me, send: Send): Pair<List<Member>, Int> {
        val r = call(send, seal(JSONObject().put("op", "members"), me)); val a = r.getJSONArray("members")
        return List(a.length()) { a.getJSONObject(it).let { m -> Member(m.getString("key"), m.getInt("i"), m.getString("name"), m.getString("kind"), m.has("chip"), m.getBoolean("blocked"), m.getLong("added")) } } to r.getInt("next")
    }
    fun block(me: Me, h: Held, key: String, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "block").put("key", key), me)) }
    /** Needs the fingerprint. */
    fun unblock(me: Me, h: Held, key: String, fp: Fingerprint, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "unblock").put("key", key), me, fp)) }

    /** Adds a device. Needs the fingerprint. This device and the box each give half of the newcomer's piece. */
    fun add(me: Me, h: Held, inv: Invite, fp: Fingerprint, send: Send = http(h.addr)): Int {
        val (list, i) = listing(me, send)
        val boxI = list.firstOrNull { it.key == h.boxKey }?.i ?: refuse("no_box")
        var mine = emptyMap<Int, String>()
        val member = JSONObject().put("key", inv.key).put("name", inv.name).put("kind", "device").put("i", i).apply { if (inv.chip != null) put("chip", inv.chip) }
        val r = current(me, h, send, fp) {
            mine = Frost.repairDeltas(h.piece, listOf(h.piece.i, boxI).sorted(), i)
            JSONObject().put("op", "add").put("member", member).put("delta", Seal.to(me.sk, h.boxKey, "repair-delta", mine[boxI]!!))
        }
        val sigma = Frost.repairSigma(listOf(mine[h.piece.i]!!, Seal.from(me.sk, h.boxKey, "repair-delta", r.getString("delta"))))
        call(send, seal(JSONObject().put("op", "welcome_put").put("key", inv.key).put("sigma", Seal.to(me.sk, inv.key, "repair-sigma", sigma)), me))
        return i
    }

    /** The new device's side: collect both halves and build its piece. */
    fun join(me: Me, j: JoinText, send: Send = http(j.addr)): Held {
        val r = call(send, seal(JSONObject().put("op", "welcome"), me))
        if (r.getString("npub") != j.npub) refuse("wrong_account")
        val c = r.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }
        if (c.size != 2 || c[0].substring(2) != j.npub) refuse("wrong_account")
        val sigmas = listOf(Seal.from(me.sk, j.boxKey, "repair-sigma", r.getString("box")), Seal.from(me.sk, r.getString("from"), "repair-sigma", r.getString("device")))
        return Held(Piece(c, r.getInt("i"), Frost.repairShare(c, sigmas, r.getInt("i"))), j.npub, j.boxKey, j.addr, r.optInt("epoch", 0))
    }

    /** Falls back to the nsec. Needs the fingerprint. The only place a whole key ever exists. */
    fun formNsec(me: Me, h: Held, fp: Fingerprint, send: Send = http(h.addr)): String {
        val r = current(me, h, send, fp) { JSONObject().put("op", "reveal") }
        val boxShare = BigInteger(Seal.from(me.sk, h.boxKey, "reveal", r.getString("share")), 16)
        val (x1, x2) = BigInteger.valueOf(h.piece.i.toLong()) to BigInteger.valueOf(r.getInt("i").toLong())
        // The line at 0 from its values at x1 and x2.
        val inv = x2.subtract(x1).modInverse(N)
        val nsec = h.piece.share.multiply(x2).subtract(boxShare.multiply(x1)).multiply(inv).mod(N)
        if (Secp.mulG(nsec).substring(2) != h.npub) refuse("bad_piece")
        return scalarHex(nsec)
    }

    /** Cycles the keys. Needs the fingerprint. Blocked devices are dropped for good; the key does not change. */
    fun cycle(me: Me, h: Held, fp: Fingerprint, send: Send = http(h.addr)) {
        val list = members(me, h, send)
        var b1 = BigInteger.ZERO
        val r = current(me, h, send, fp) {
            b1 = BigInteger(1, random(32)).mod(N)
            val changes = JSONObject()
            for (m in list) if (!m.blocked && m.key != me.key && m.key != h.boxKey) changes.put(m.key, Seal.to(me.sk, m.key, "cycle", scalarHex(b1.multiply(BigInteger.valueOf(m.i.toLong())))))
            JSONObject().put("op", "cycle").put("b1", Seal.to(me.sk, h.boxKey, "cycle", scalarHex(b1))).put("changes", changes)
        }
        val c = r.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }
        adopt(h, c, h.piece.share.add(b1.multiply(BigInteger.valueOf(h.piece.i.toLong()))).mod(N), r.getInt("epoch"))
    }

    /** Logs a browser in to the box's page, from the code that page shows. Needs the fingerprint. */
    fun approveLogin(me: Me, h: Held, text: String, fp: Fingerprint, send: Send = http(h.addr)) {
        val q = try { JSONObject(text).getJSONObject("login") } catch (_: Exception) { refuse("bad_qr") }
        if (q.optString("key") != h.boxKey) refuse("wrong_box")
        call(send, seal(JSONObject().put("op", "login").put("code", q.getString("code")), me, fp))
    }

    /** The NIP-44 conversation key with `peer` (x-only hex), made with the box. The key is never whole. */
    fun conversationKey(me: Me, h: Held, peer: String, send: Send = http(h.addr)): ByteArray {
        if (!Regex("^[0-9a-f]{64}$").matches(peer)) refuse("bad_peer")
        val r = current(me, h, send) { JSONObject().put("op", "ecdh").put("peer", peer) }
        // This piece's part: λ·share·Q, with λ = other / (other − i) for the pair of pieces taking part.
        val (i, o) = BigInteger.valueOf(h.piece.i.toLong()) to BigInteger.valueOf(r.getInt("i").toLong())
        val lambda = o.multiply(o.subtract(i).modInverse(N)).mod(N)
        val mine = Secp.mul(lambda.multiply(h.piece.share).mod(N), "02$peer")
        return Nip44.conversationKey(unhex(Secp.add(mine, r.getString("part")).substring(2)))
    }
    fun nip44Encrypt(me: Me, h: Held, peer: String, text: String, send: Send = http(h.addr)) = Nip44.encrypt(text, conversationKey(me, h, peer, send))
    fun nip44Decrypt(me: Me, h: Held, peer: String, payload: String, send: Send = http(h.addr)) = Nip44.decrypt(payload, conversationKey(me, h, peer, send))
}
