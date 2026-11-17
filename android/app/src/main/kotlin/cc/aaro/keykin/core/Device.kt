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
/** `piece` and `epoch` change when the keys are cycled, `boxKey` and `addr` when the account moves box; `changed` is told, so the app can save. */
class Held(var piece: Piece, val npub: String, var boxKey: String, var addr: String, var epoch: Int = 0) {
    var changed: (Held) -> Unit = {}
    fun json(): JSONObject = JSONObject().put("commitment", JSONArray(piece.c)).put("i", piece.i).put("share", scalarHex(piece.share)).put("npub", npub).put("boxKey", boxKey).put("addr", addr).put("epoch", epoch)
    override fun equals(other: Any?) = other is Held && other.json().toString() == json().toString()
    override fun hashCode() = json().toString().hashCode()
    companion object {
        fun of(o: JSONObject) = Held(Piece(o.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }, o.getInt("i"), BigInteger(o.getString("share"), 16)), o.getString("npub"), o.getString("boxKey"), o.getString("addr"), o.optInt("epoch", 0))
    }
}
data class Member(val key: String, val i: Int, val name: String, val kind: String, val chip: Boolean, val blocked: Boolean, val added: Long, val addr: String? = null)
data class Qr(val addr: String, val key: String, val code: String)
data class Invite(val key: String, val name: String, val chip: String?)
data class JoinText(val addr: String, val boxKey: String, val npub: String)
/** A site's nostrconnect:// code (NIP-46): its own key, the relays it listens on, the secret to echo, and what it calls itself. */
data class ConnectCode(val client: String, val relays: List<String>, val secret: String, val name: String?, val url: String?)

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

    /** Reads a site's nostrconnect:// code. At most five relays, `ws://` or `wss://`; `url` is kept as its origin. */
    fun nostrConnect(text: String): ConnectCode {
        val t = text.trim()
        if (!t.startsWith("nostrconnect://")) refuse("bad_code")
        val rest = t.removePrefix("nostrconnect://")
        val client = rest.substringBefore('?').substringBefore('/').lowercase()
        if (!KEY.matches(client)) refuse("bad_code")
        val params = rest.substringAfter('?', "").split('&').filter { it.contains('=') }.map {
            java.net.URLDecoder.decode(it.substringBefore('='), "UTF-8") to java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8")
        }
        val relays = params.filter { it.first == "relay" }.map { it.second.trim() }.filter { Regex("^wss?://\\S+$").matches(it) }.distinct().take(5)
        val secret = params.firstOrNull { it.first == "secret" }?.second ?: ""
        if (relays.isEmpty() || secret.isEmpty() || secret.length > 200) refuse("bad_code")
        val url = params.firstOrNull { it.first == "url" }?.second?.let { u ->
            try { java.net.URI(u).let { if (it.scheme == "https" || it.scheme == "http") "${it.scheme}://${it.authority}" else null } } catch (_: Exception) { null }
        }
        return ConnectCode(client, relays, secret, params.firstOrNull { it.first == "name" }?.second?.take(60)?.ifEmpty { null }, url)
    }
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
            val r = send(seal(body().put("epoch", h.epoch).put("account", h.npub), me, fp))
            if (r.optString("error") != "stale" || tries++ > 0 || r.optJSONArray("catchups") == null) { if (r.has("error")) refuse(r.getString("error")); return r }
            var share = h.piece.share
            val cs = r.getJSONArray("catchups")
            for (k in 0 until cs.length()) cs.getJSONObject(k).let { c -> share = share.add(BigInteger(Seal.from(me.sk, c.getString("from"), "cycle", c.getString("sealed")), 16)).mod(N) }
            val c = r.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }
            adopt(h, c, share, r.getInt("epoch"))
            call(send, seal(JSONObject().put("op", "caught_up").put("account", h.npub), me))
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

    /**
     * Asks the box first and, if it cannot be reached, other devices that listen (a computer that stays
     * on). Only signing and message keys can be done without the box.
     */
    fun withHelpers(box: Send, helpers: List<Send>): Send = { req ->
        try { box(req) } catch (e: KeykinException) {
            val op = req.optJSONObject("body")?.optString("op")
            if (e.code != "no_box" || (op != "sign" && op != "ecdh")) throw e
            var last: JSONObject? = null
            for (h in helpers) { try { val r = h(req); if (!r.has("error")) { last = r; break }; last = r } catch (_: KeykinException) { } }
            last ?: throw e
        }
    }

    /** After scanning the box's QR: the device and the box make the key together. No whole key exists. */
    fun create(me: Me, qr: Qr, send: Send = http(qr.addr)): Held {
        val one = Frost.dkg1(1)
        val r1 = call(send, seal(JSONObject().put("op", "create1").put("request", qr.code).put("code", qr.code).put("pkg", one.pkg).put("name", me.name).apply { if (me.chip != null) put("chip", me.chip) }, me))
        val box = listOf(2 to r1.getString("pkg"))
        val two = Frost.dkg2(one.secret, box)
        val r2 = call(send, seal(JSONObject().put("op", "create2").put("request", qr.code).put("pkg2", Seal.to(me.sk, qr.key, "keygen", two.pkgFor[2] ?: refuse("bad_keygen"))), me))
        val done = Frost.dkg3(two.secret, box, listOf(2 to Seal.from(me.sk, qr.key, "keygen", r2.getString("pkg2"))))
        if (done.npub != r2.getString("npub")) refuse("bad_keygen")
        return Held(Piece(done.c, 1, done.share), done.npub, qr.key, qr.addr)
    }

    /**
     * Brings in a key the person already has (hex). This device splits it, keeps one piece and sends the
     * box the other, sealed. The caller KEEPS the whole key, encrypted at rest, as the tier 1 backup. It is
     * forgotten only when the person chooses to.
     */
    fun importKey(me: Me, qr: Qr, nsecHex: String, send: Send = http(qr.addr)): Held {
        if (!Regex("^[0-9a-f]{64}$").matches(nsecHex)) refuse("bad_key")
        var a0 = BigInteger(nsecHex, 16).mod(N)
        if (a0.signum() == 0) refuse("bad_key")
        if (Secp.mulG(a0).startsWith("03")) a0 = N.subtract(a0)          // the form whose public key has even y (BIP-340)
        var a1 = BigInteger(1, random(32)).mod(N)
        while (a1.signum() == 0) a1 = BigInteger(1, random(32)).mod(N)
        val c = listOf(Secp.mulG(a0), Secp.mulG(a1))
        val piece = { i: Int -> a0.add(a1.multiply(BigInteger.valueOf(i.toLong()))).mod(N) }
        val npub = c[0].substring(2)
        val r = call(send, seal(JSONObject().put("op", "import").put("request", qr.code).put("commitment", JSONArray(c))
            .put("share", Seal.to(me.sk, qr.key, "import", scalarHex(piece(2)))).put("name", me.name).apply { if (me.chip != null) put("chip", me.chip) }, me))
        if (r.getString("npub") != npub) refuse("bad_keygen")
        return Held(Piece(c, 1, piece(1)), npub, qr.key, qr.addr)
    }

    /** Signs a Nostr event with the box. Returns the whole signed event. */
    /** `grant` names the site or app this signature is for (SPEC 11.5); leave it null for the person's own use. */
    fun sign(me: Me, h: Held, kind: Int, content: String, tags: List<List<String>> = emptyList(), createdAt: Long = now(), send: Send = http(h.addr), grant: String? = null, tapped: Boolean = false): JSONObject {
        val id = eventId(h.npub, createdAt, kind, tags, content)
        val ev = JSONObject().put("pubkey", h.npub).put("created_at", createdAt).put("kind", kind).put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content)
        lateinit var mine: Frost.Asked
        val r = current(me, h, send) { mine = Frost.ask(h.piece, id); JSONObject().put("op", "sign").put("event", ev).put("commit", mine.commit.json()).apply { if (grant != null) put("grant", grant); if (tapped) put("tapped", true) } }
        if (r.getString("id") != id) refuse("wrong_id")
        val c = r.getJSONObject("commit")
        return ev.put("id", id).put("sig", Frost.finish(h.piece, id, mine, Commit(c.getInt("i"), c.getString("D"), c.getString("E")), r.getString("z")))
    }

    fun members(me: Me, h: Held, send: Send = http(h.addr)): List<Member> = listing(me, h, send).first
    private fun listing(me: Me, h: Held, send: Send): Pair<List<Member>, Int> = listed(call(send, seal(JSONObject().put("op", "members").put("account", h.npub), me)))
    private fun listed(r: JSONObject): Pair<List<Member>, Int> {
        val a = r.getJSONArray("members")
        return List(a.length()) { a.getJSONObject(it).let { m -> Member(m.getString("key"), m.getInt("i"), m.getString("name"), m.getString("kind"), m.has("chip"), m.getBoolean("blocked"), m.getLong("added"), if (m.has("addr")) m.getString("addr") else null) } } to r.getInt("next")
    }
    fun block(me: Me, h: Held, key: String, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "block").put("account", h.npub).put("key", key), me)) }
    /** Needs the fingerprint. */
    fun unblock(me: Me, h: Held, key: String, fp: Fingerprint, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "unblock").put("account", h.npub).put("key", key), me, fp)) }

    /** Adds a device. Needs the fingerprint. This device and the box each give half of the newcomer's piece. */
    /** `note`: a signed-in account page asked for this (SPEC 11.6); then no fingerprint is needed and `fp` may be null. */
    /** `kind` is `box` for a second box (its member key from its setup code as `inv.key`). */
    fun add(me: Me, h: Held, inv: Invite, fp: Fingerprint?, send: Send = http(h.addr), note: String? = null, kind: String = "device"): Int {
        val (list, i) = listing(me, h, send)
        val boxI = list.firstOrNull { it.key == h.boxKey }?.i ?: refuse("no_box")
        var mine = emptyMap<Int, String>()
        val member = JSONObject().put("key", inv.key).put("name", inv.name).put("kind", kind).put("i", i).apply { if (inv.chip != null) put("chip", inv.chip) }
        val r = current(me, h, send, if (note != null) null else fp) {
            mine = Frost.repairDeltas(h.piece, listOf(h.piece.i, boxI).sorted(), i)
            JSONObject().put("op", "add").put("member", member).put("delta", Seal.to(me.sk, h.boxKey, "repair-delta", mine[boxI]!!)).apply { if (note != null) put("note", note) }
        }
        val sigma = Frost.repairSigma(listOf(mine[h.piece.i]!!, Seal.from(me.sk, h.boxKey, "repair-delta", r.getString("delta"))))
        call(send, seal(JSONObject().put("op", "welcome_put").put("account", h.npub).put("key", inv.key).put("sigma", Seal.to(me.sk, inv.key, "repair-sigma", sigma)), me))
        return i
    }

    /** The new device's side: collect both halves and build its piece. */
    fun join(me: Me, j: JoinText, send: Send = http(j.addr)): Held {
        val r = call(send, seal(JSONObject().put("op", "welcome").put("account", j.npub), me))
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
    /** `note`: a signed-in account page asked and the person tapped Yes on this device, in place of the fingerprint. */
    fun cycle(me: Me, h: Held, fp: Fingerprint?, send: Send = http(h.addr), note: String? = null) {
        val list = members(me, h, send)
        var b1 = BigInteger.ZERO
        val r = current(me, h, send, if (note != null) null else fp) {
            b1 = BigInteger(1, random(32)).mod(N)
            val changes = JSONObject()
            for (m in list) if (!m.blocked && m.key != me.key && m.key != h.boxKey) changes.put(m.key, Seal.to(me.sk, m.key, "cycle", scalarHex(b1.multiply(BigInteger.valueOf(m.i.toLong())))))
            JSONObject().put("op", "cycle").put("b1", Seal.to(me.sk, h.boxKey, "cycle", scalarHex(b1))).put("changes", changes).apply { if (note != null) put("note", note) }
        }
        val c = r.getJSONArray("commitment").let { a -> List(a.length()) { a.getString(it) } }
        adopt(h, c, h.piece.share.add(b1.multiply(BigInteger.valueOf(h.piece.i.toLong()))).mod(N), r.getInt("epoch"))
    }

    /** Logs a browser in to the box's page, from the code that page shows. Needs the fingerprint. */
    fun approveLogin(me: Me, h: Held, text: String, fp: Fingerprint, send: Send = http(h.addr)) {
        val q = try { JSONObject(text).getJSONObject("login") } catch (_: Exception) { refuse("bad_qr") }
        if (q.optString("key") != h.boxKey) refuse("wrong_box")
        call(send, seal(JSONObject().put("op", "login").put("account", h.npub).put("code", q.getString("code")), me, fp))
    }

    /** The NIP-44 conversation key with `peer` (x-only hex), made with the box. The key is never whole. */
    fun conversationKey(me: Me, h: Held, peer: String, send: Send = http(h.addr), grant: String? = null): ByteArray {
        if (!Regex("^[0-9a-f]{64}$").matches(peer)) refuse("bad_peer")
        val r = current(me, h, send) { JSONObject().put("op", "ecdh").put("peer", peer).apply { if (grant != null) put("grant", grant) } }
        // This piece's part: λ·share·Q, with λ = other / (other − i) for the pair of pieces taking part.
        val (i, o) = BigInteger.valueOf(h.piece.i.toLong()) to BigInteger.valueOf(r.getInt("i").toLong())
        val lambda = o.multiply(o.subtract(i).modInverse(N)).mod(N)
        val mine = Secp.mul(lambda.multiply(h.piece.share).mod(N), "02$peer")
        return Nip44.conversationKey(unhex(Secp.add(mine, r.getString("part")).substring(2)))
    }
    fun nip44Encrypt(me: Me, h: Held, peer: String, text: String, send: Send = http(h.addr), grant: String? = null) = Nip44.encrypt(text, conversationKey(me, h, peer, send, grant))
    fun nip44Decrypt(me: Me, h: Held, peer: String, payload: String, send: Send = http(h.addr), grant: String? = null) = Nip44.decrypt(payload, conversationKey(me, h, peer, send, grant))

    // --- Asking for an account on a box that needs the admin's yes (SPEC 11.4) ------------------------

    /** Asks to make an account (`make`) or move one here (`transfer`). Returns the request id to wait on. */
    fun ask(me: Me, what: String, note: String, send: Send, account: String? = null): String =
        call(send, seal(JSONObject().put("op", "ask").put("what", what).put("name", me.name).put("note", note).apply { if (me.chip != null) put("chip", me.chip); if (account != null) put("account", account) }, me)).getString("request")
    /** `waiting`, `approved`, `refused` or `gone`. Once approved, use the id as the `code` of a Qr for `create`. */
    fun asked(me: Me, request: String, send: Send): String = call(send, seal(JSONObject().put("op", "asked").put("request", request), me)).getString("state")
    /** The state, and the box's member key: what `Qr(addr, key, request)` needs when the phone only had the address. */
    fun askedWithKey(me: Me, request: String, send: Send): Pair<String, String> =
        call(send, seal(JSONObject().put("op", "asked").put("request", request), me)).let { it.getString("state") to it.getString("key") }
    /** Takes the request back. Only the device that asked can. */
    fun askCancel(me: Me, request: String, send: Send) { call(send, seal(JSONObject().put("op", "ask_cancel").put("request", request), me)) }

    // --- Username and password for the account page (SPEC 11.3) --------------------------------------

    /** The verifier for a password: PBKDF2-HMAC-SHA256, 600000 rounds, 32 bytes, over the NFKC form. Hex. */
    fun passwordVerifier(password: String, saltHex: String): String {
        val spec = javax.crypto.spec.PBEKeySpec(java.text.Normalizer.normalize(password, java.text.Normalizer.Form.NFKC).toCharArray(), unhex(saltHex), 600000, 256)
        return hex(javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded)
    }
    /** Sets or changes the username and password. Needs the fingerprint. The box never sees the password. */
    fun passwordSet(me: Me, h: Held, username: String, password: String, fp: Fingerprint, send: Send = http(h.addr)) {
        val salt = hex(random(16))
        val check = hex(sha256(utf8("keykin2-pw"), unhex(passwordVerifier(password, salt))))
        call(send, seal(JSONObject().put("op", "password_set").put("account", h.npub).put("username", username).put("salt", salt).put("check", check), me, fp))
    }
    fun passwordClear(me: Me, h: Held, fp: Fingerprint, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "password_clear").put("account", h.npub), me, fp)) }

    // --- What this device has let in, and revoking (SPEC 11.5) ---------------------------------------

    /** Tells the box this device's whole list. Returns the ids that were revoked, to drop from the list. */
    fun reportGrants(me: Me, h: Held, grants: List<Grant>, send: Send = http(h.addr)): List<String> {
        val r = call(send, seal(JSONObject().put("op", "grants").put("account", h.npub).put("grants", JSONArray(grants.map { it.json() })), me)).getJSONArray("revoked")
        return List(r.length()) { r.getString(it) }
    }
    fun revoke(me: Me, h: Held, grant: String, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "revoke").put("account", h.npub).put("grant", grant), me)) }
    /** Limits a grant to posting (`"posts"`): the box then signs only posts for it and gives it no message keys. `null` lifts it. */
    fun limit(me: Me, h: Held, grant: String, to: String?, send: Send = http(h.addr)) {
        call(send, seal(JSONObject().put("op", "limit").put("account", h.npub).put("grant", grant).put("to", to ?: JSONObject.NULL), me))
    }

    // --- Things the account page started for a device to finish (SPEC 11.6) --------------------------

    fun notes(me: Me, h: Held, send: Send = http(h.addr)): List<Note> {
        val a = call(send, seal(JSONObject().put("op", "notes").put("account", h.npub), me)).getJSONArray("notes")
        return List(a.length()) { a.getJSONObject(it).let { n -> Note(n.getString("id"), n.getString("kind"), n.getString("text"), n.getLong("at"), n.optBoolean("tap", false)) } }
    }
    /** The person tapped No. The note goes, and the browser that asked is signed out of the account page. */
    fun noteRefuse(me: Me, h: Held, note: String, send: Send = http(h.addr)) { call(send, seal(JSONObject().put("op", "note_refuse").put("account", h.npub).put("note", note), me)) }
    fun noteDone(me: Me, h: Held, note: String, result: String, send: Send = http(h.addr)) {
        call(send, seal(JSONObject().put("op", "note_done").put("account", h.npub).put("note", note).put("result", result), me))
    }

    // --- Moving the account to another box (SPEC 11.4) -------------------------------------------------

    /**
     * Moves the account to another Keykin box. Needs the fingerprint. The key is never whole: this device and
     * the old box give the new box its piece, then the keys are cycled on the new box so the old box's piece
     * stops fitting. `h` then points at the new box (`changed` is told). Hand the other devices `Texts.join(h)`;
     * they call `moved` with it and catch up on their next request.
     */
    fun transferToBox(me: Me, h: Held, newBox: Qr, fp: Fingerprint, oldSend: Send = http(h.addr), newSend: Send = http(newBox.addr)) {
        if (newBox.key == h.boxKey) refuse("same_box")
        val oldBox = h.boxKey
        add(me, h, Invite(newBox.key, "New box", null), fp, oldSend, kind = "box")
        val one = call(newSend, seal(JSONObject().put("op", "transfer1").put("request", newBox.code).put("account", h.npub), me))
        val welcome = call(oldSend, one.getJSONObject("welcome"))
        val list = call(oldSend, seal(JSONObject().put("op", "members").put("account", h.npub), me))
        call(newSend, seal(JSONObject().put("op", "transfer2").put("request", newBox.code).put("welcome", welcome).put("oldBox", oldBox)
            .put("members", list.getJSONArray("members")).put("next", list.getInt("next")), me))
        h.boxKey = newBox.key; h.addr = newBox.addr; h.changed(h)
        cycle(me, h, fp, newSend)          // the old box gets no change, so its piece is dead
    }

    /**
     * Another device moved the account: from now on this one uses the box the join text names. Its piece does
     * not change here; it catches up on its next request. Refuses a join text for another account, or an
     * address whose box has another key.
     */
    fun moved(me: Me, h: Held, j: JoinText, send: Send = http(j.addr)) {
        if (j.npub != h.npub) refuse("wrong_account")
        val r = call(send, seal(JSONObject().put("op", "members").put("account", h.npub), me))
        if (r.getString("boxKey") != j.boxKey) refuse("wrong_box")
        h.boxKey = j.boxKey; h.addr = j.addr; h.changed(h)
    }
}

/** A site or app this device has let in (SPEC 11.5). `kind` is `site` or `app`. */
data class Grant(val id: String, val kind: String, val name: String, val since: Long) {
    fun json(): JSONObject = JSONObject().put("id", id).put("kind", kind).put("name", name).put("since", since)
    companion object { fun new(kind: String, name: String) = Grant(hex(random(16)), kind, name, System.currentTimeMillis() / 1000) }
}
/**
 * Something the account page started for a device to finish. `kind` is `nostrconnect`, `invite`, `bunker`
 * or `cycle`. A signed-in account page has the person's authority, so the device just does it, except when
 * `tap` is true: then it shows Yes or No first (no fingerprint), and No is `Device.noteRefuse`.
 */
data class Note(val id: String, val kind: String, val text: String, val at: Long, val tap: Boolean = false)

/** The few signatures that are hard to undo. The device asks Yes or No, then signs with `tapped = true`. */
object Destructive {
    /** Why an event is hard to undo, in a few words, or null if it is ordinary. */
    fun why(kind: Int, tags: List<List<String>>, content: String): String? = when {
        kind == 62 -> "asks every relay to erase the whole account"
        kind == 5 && tags.count { it.firstOrNull() == "e" || it.firstOrNull() == "a" } >= 5 -> "deletes five or more posts at once"
        kind == 3 && tags.none { it.firstOrNull() == "p" } -> "empties the follow list"
        kind == 0 -> {
            val p = try { JSONObject(content) } catch (_: Exception) { null }
            if (p == null || listOf("name", "display_name", "about", "picture", "nip05", "lud16").none { k -> p.optString(k).trim().isNotEmpty() }) "empties the profile" else null
        }
        else -> null
    }
}
