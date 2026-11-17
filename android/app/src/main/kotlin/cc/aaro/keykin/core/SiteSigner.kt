// This device as a remote signer for sites (NIP-46), reached through relays. A site gets in with a
// single-use ticket (QRST signer-ticket): the person scanned the site's code and said yes, the ticket
// went to the site sealed, and the site presents it here as the secret of `connect`. From then on the
// site has a key of its own on the list, which can be signed out. Every signature still needs the box.
package cc.aaro.keykin.core

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class SiteSigner(
    private val me: Me,
    private val held: () -> Held?,
    private val send: (Held) -> Send,
    /** The saved state (see `fresh`), and what to call when it changes. */
    private val state: JSONObject,
    private val changed: (JSONObject) -> Unit,
    private val log: (String) -> Unit = {},
) {
    companion object {
        const val TICKET_SECONDS = 900L
        fun fresh(): JSONObject = JSONObject().put("sk", hex(random(32))).put("clients", JSONArray()).put("tickets", JSONArray())
    }
    data class Site(val key: String, val origin: String?, val relays: List<String>)

    private val sk = unhex(state.getString("sk"))
    val pubkey: String = Secp.pub(sk)
    private val http = OkHttpClient.Builder().pingInterval(25, TimeUnit.SECONDS).build()
    private val sockets = ConcurrentHashMap<String, WebSocket>()
    private val seen = java.util.Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
    @Volatile private var running = false
    private fun now() = System.currentTimeMillis() / 1000
    private fun <T> list(name: String, f: (JSONObject) -> T): List<T> = state.optJSONArray(name)?.let { a -> List(a.length()) { f(a.getJSONObject(it)) } } ?: emptyList()
    private fun strings(a: JSONArray?) = a?.let { List(it.length()) { i -> it.getString(i) } } ?: emptyList()

    fun sites(): List<Site> = synchronized(state) { list("clients") { Site(it.getString("key"), if (it.has("origin")) it.getString("origin") else null, strings(it.optJSONArray("relays"))) } }

    /** A ticket for `origin`, good once and for 15 minutes, to be handed to the site that showed the code. */
    fun mint(origin: String?, relays: List<String>): JSONObject {
        val h = held() ?: refuse("no_account")
        val t = JSONObject().put("v", 1).put("pubkey", h.npub).put("signer", pubkey).put("relays", JSONArray(relays)).put("t", hex(random(16))).put("expires", now() + TICKET_SECONDS)
        synchronized(state) {
            state.getJSONArray("tickets").put(JSONObject().put("t", t.getString("t")).put("expires", t.getLong("expires")).put("relays", JSONArray(relays)).apply { if (origin != null) put("origin", origin) })
            changed(state)
        }
        start()
        return t
    }

    fun signOut(key: String) {
        synchronized(state) {
            val keep = JSONArray(); val a = state.getJSONArray("clients")
            for (i in 0 until a.length()) if (a.getJSONObject(i).getString("key") != key) keep.put(a.getJSONObject(i))
            state.put("clients", keep); changed(state)
        }
    }

    /** Listens on every relay a site or a waiting ticket names. Safe to call again. */
    fun start() {
        running = true
        val wanted = synchronized(state) {
            val live = JSONArray(); val a = state.getJSONArray("tickets")
            for (i in 0 until a.length()) if (a.getJSONObject(i).getLong("expires") > now()) live.put(a.getJSONObject(i))
            state.put("tickets", live)
            (list("clients") { strings(it.optJSONArray("relays")) } + list("tickets") { strings(it.optJSONArray("relays")) }).flatten().toSet()
        }
        for (url in wanted) if (!sockets.containsKey(url)) open(url)
    }
    fun stop() { running = false; sockets.values.forEach { it.close(1000, null) }; sockets.clear() }

    private fun open(url: String) {
        val ws = http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                log("listening on $url")
                ws.send(JSONArray().put("REQ").put("keykin").put(JSONObject().put("kinds", JSONArray().put(24133)).put("#p", JSONArray().put(pubkey)).put("since", now() - 10)).toString())
            }
            override fun onMessage(ws: WebSocket, text: String) {
                try { val m = JSONArray(text); if (m.optString(0) == "EVENT") Thread { onEvent(ws, m.getJSONObject(2)) }.apply { isDaemon = true }.start() } catch (_: Exception) { }
            }
            override fun onClosed(ws: WebSocket, code: Int, reason: String) = lost(url, ws)
            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) { log("relay $url failed: ${t.message}"); lost(url, ws) }
        })
        sockets[url] = ws
    }
    private fun lost(url: String, ws: WebSocket) {
        if (!sockets.remove(url, ws) || !running) return
        Thread { Thread.sleep(4000); if (running) start() }.apply { isDaemon = true }.start()
    }

    private fun onEvent(ws: WebSocket, ev: JSONObject) {
        val id = ev.optString("id"); val client = ev.optString("pubkey")
        if (ev.optInt("kind") != 24133 || !seen.add(id) || !Regex("^[0-9a-f]{64}$").matches(client)) return
        val key = Nip44.conversationKey(Secp.ecdhX(sk, client))
        val req = try { JSONObject(Nip44.decrypt(ev.getString("content"), key)) } catch (e: Exception) { log("unreadable request from ${client.take(8)}: ${e.message}"); return }
        val body = JSONObject().put("id", req.optString("id"))
        try { body.put("result", answer(client, req.optString("method"), strings(req.optJSONArray("params")))) }
        catch (e: KeykinException) { body.put("error", e.code) } catch (e: Exception) { body.put("error", "failed") }
        log("site ${client.take(8)} ${req.optString("method")} -> ${body.optString("error", "ok")}")
        val tags = listOf(listOf("p", client)); val at = now(); val content = Nip44.encrypt(body.toString(), key)
        val eid = eventId(pubkey, at, 24133, tags, content)
        val out = JSONObject().put("id", eid).put("pubkey", pubkey).put("created_at", at).put("kind", 24133)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", Secp.schnorrSign(unhex(eid), sk))
        ws.send(JSONArray().put("EVENT").put(out).toString())
    }

    private fun known(client: String) = sites().any { it.key == client }

    /** One request from a site. Returns the NIP-46 `result`, or throws. */
    fun answer(client: String, method: String, params: List<String>): String {
        if (method == "connect") {
            if (!known(client)) synchronized(state) {
                val a = state.getJSONArray("tickets"); val keep = JSONArray(); var ticket: JSONObject? = null
                for (i in 0 until a.length()) { val t = a.getJSONObject(i); if (ticket == null && t.getString("t") == params.getOrNull(1) && t.getLong("expires") > now()) ticket = t else keep.put(t) }
                val t = ticket ?: refuse("bad_secret")          // a ticket works once
                state.put("tickets", keep)
                state.getJSONArray("clients").put(JSONObject().put("key", client).put("relays", t.optJSONArray("relays") ?: JSONArray()).apply { if (t.has("origin")) put("origin", t.getString("origin")) })
                changed(state)
            }
            return params.getOrNull(1)?.takeIf { it.isNotEmpty() } ?: "ack"
        }
        if (!known(client)) refuse("not_connected")
        val h = held() ?: refuse("no_account")
        return when (method) {
            "ping" -> "pong"
            "get_public_key" -> h.npub
            "sign_event" -> {
                val e = JSONObject(params[0])
                val tags = (e.optJSONArray("tags") ?: JSONArray()).let { a -> List(a.length()) { i -> a.getJSONArray(i).let { t -> List(t.length()) { t.getString(it) } } } }
                Device.sign(me, h, e.getInt("kind"), e.optString("content", ""), tags, if (e.has("created_at")) e.getLong("created_at") else now(), send(h)).toString()
            }
            "nip44_encrypt" -> Device.nip44Encrypt(me, h, params[0], params[1], send(h))
            "nip44_decrypt" -> Device.nip44Decrypt(me, h, params[0], params[1], send(h))
            else -> refuse("unsupported")
        }
    }
}
