// The Kotlin device against real boxes (the TypeScript ones). `node tools/kotlin-test.ts` starts them and a
// relay, gives each test that makes an account its own setup code, and runs these; without its environment the
// tests that need a box are skipped. A software P-256 key stands in for the phone's chip.
package cc.aaro.keykin

import cc.aaro.keykin.core.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class BoxInteropTest {
    private class SoftChip {
        private val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val pub: String = Der.compressed(kp.public as ECPublicKey)
        val fp: Fingerprint = { m -> Der.toCompact(Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private); update(m) }.sign()) }
    }
    private fun device(name: String): Pair<Me, SoftChip> { val c = SoftChip(); return Me(random(32), name, c.pub) to c }

    @Test fun canonicalTextMatchesTheBox() {
        assertEquals("""{"a":[1,"x\n\"é😀"],"b":{"c":true,"d":null}}""", jcs(JSONObject("""{"b":{"d":null,"c":true},"a":[1,"x\n\"é😀"]}""")))
        assertEquals("\"\\u0001\\b\\t\"", jsonString("\u0001\b\t"))
    }

    @Test fun sealedValuesRoundTrip() {
        val (a, b) = random(32) to random(32)
        val s = Seal.to(a, Secp.pub(b), "reveal", "ab".repeat(32))
        assertEquals("ab".repeat(32), Seal.from(b, Secp.pub(a), "reveal", s))
        assertThrows(KeykinException::class.java) { Seal.from(b, Secp.pub(a), "keygen", s) }
    }

    @Test fun createSignAddJoinBlockAndFormTheNsec() {
        val qrText = System.getenv("KEYKIN_BOX_QR") ?: ""
        assumeTrue("set KEYKIN_BOX_QR to the box's setup text", qrText.isNotEmpty())
        val (phone, chip) = device("Pixel (Kotlin)")
        val held = Device.create(phone, Texts.qr(qrText))
        assertEquals(1, held.piece.i)

        val ev = Device.sign(phone, held, 1, "from Kotlin \"quoted\" \n é😀", listOf(listOf("t", "keykin")))
        assertTrue(Secp.schnorrVerify(ev.getString("sig"), unhex(ev.getString("id")), held.npub))

        // A second device joins through the invite and join texts.
        val (tablet, tabletChip) = device("Tablet (Kotlin)")
        assertEquals(3, Device.add(phone, held, Texts.readInvite(Texts.invite(tablet)), chip.fp))
        val th = Device.join(tablet, Texts.readJoin(Texts.join(held)))
        val ev2 = Device.sign(tablet, th, 1, "from the tablet")
        assertTrue(Secp.schnorrVerify(ev2.getString("sig"), unhex(ev2.getString("id")), held.npub))
        assertEquals(Held.of(th.json()), th)

        // The fingerprint is needed, and it must be this device's own chip.
        assertEquals("needs_fingerprint", assertThrows(KeykinException::class.java) { Device.formNsec(phone, held, tabletChip.fp) }.code)
        val nsec = Device.formNsec(phone, held, chip.fp)
        assertEquals(held.npub, Secp.pub(unhex(nsec)))
        assertEquals(nsec, Device.formNsec(tablet, th, tabletChip.fp))

        // Blocking needs no fingerprint; unblocking does.
        Device.block(tablet, th, phone.key)
        assertEquals("blocked", assertThrows(KeykinException::class.java) { Device.sign(phone, held, 1, "x") }.code)
        Device.unblock(tablet, th, phone.key, tabletChip.fp)
        Device.sign(phone, held, 1, "back")
        assertEquals(listOf("Pixel (Kotlin)", "Box", "Tablet (Kotlin)"), Device.members(phone, held).map { it.name })

        // Messages: two pieces make the conversation key the whole nsec would.
        val friendSk = random(32); val friend = Secp.pub(friendSk)
        val viaPieces = Device.conversationKey(phone, held, friend)
        assertArrayEquals(Nip44.conversationKey(Secp.ecdhX(unhex(nsec), friend)), viaPieces)
        val friendKey = Nip44.conversationKey(Secp.ecdhX(friendSk, held.npub))
        assertEquals("to a friend é😀", Nip44.decrypt(Device.nip44Encrypt(tablet, th, friend, "to a friend é😀"), friendKey))

        // Block, then cycle: the blocked device is gone, the other catches up by itself, the key is the same.
        Device.block(phone, held, tablet.key)
        Device.cycle(phone, held, chip.fp)
        assertEquals(1, held.epoch)
        assertEquals(listOf("Pixel (Kotlin)", "Box"), Device.members(phone, held).map { it.name })
        assertEquals("unknown_member", assertThrows(KeykinException::class.java) { Device.sign(tablet, th, 1, "x") }.code)
        assertEquals(nsec, Device.formNsec(phone, held, chip.fp))
        // A device that was away during a cycle catches up on its next request.
        val (watch, watchChip) = device("Watch (Kotlin)")
        Device.add(phone, held, Texts.readInvite(Texts.invite(watch)), chip.fp)
        val wh = Device.join(watch, Texts.readJoin(Texts.join(held)))
        Device.sign(watch, wh, 1, "collected")
        Device.cycle(phone, held, chip.fp)
        assertEquals(1, wh.epoch)
        val ev3 = Device.sign(watch, wh, 1, "after the cycle")
        assertEquals(2, wh.epoch)
        assertTrue(Secp.schnorrVerify(ev3.getString("sig"), unhex(ev3.getString("id")), held.npub))
        assertEquals(nsec, Device.formNsec(watch, wh, watchChip.fp))
    }

    @Test fun manyAccountsAskingPasswordsGrantsAndNotes() {
        // "<setup text for a first account>|<page endpoint>": the box test fixture's side.
        val env = (System.getenv("KEYKIN_BOX_MANY") ?: "").split("|")
        assumeTrue("set KEYKIN_BOX_MANY", env.size == 2)
        val qr = Texts.qr(env[0]); val send = Device.http(qr.addr)
        fun page(body: JSONObject): JSONObject {
            val c = java.net.URL(env[1]).openConnection() as java.net.HttpURLConnection
            c.requestMethod = "POST"; c.doOutput = true; c.outputStream.use { it.write(utf8(body.toString())) }
            return JSONObject(String(c.inputStream.readBytes(), Charsets.UTF_8))
        }
        val (phone, chip) = device("Pixel (Kotlin)")
        val held = Device.create(phone, qr)

        // A second person asks, and has to wait for the admin.
        val (carol, _) = device("Carol (Kotlin)")
        val id = Device.ask(carol, "make", "from the Kotlin test", send)
        assertEquals("waiting", Device.asked(carol, id, send))
        assertEquals("not_approved", assertThrows(KeykinException::class.java) { Device.create(carol, Qr(qr.addr, qr.key, id)) }.code)

        // Password: the verifier made here is the one a browser would make, and the box accepts it.
        Device.passwordSet(phone, held, "kotlin", "correct horse é", chip.fp)
        val salt = page(JSONObject().put("call", "pw_salt").put("username", "kotlin")).getString("salt")
        val session = page(JSONObject().put("call", "pw_login").put("username", "kotlin").put("verifier", Device.passwordVerifier("correct horse é", salt))).getString("session")
        assertEquals(held.npub, page(JSONObject().put("call", "me").put("session", session)).getString("npub"))

        // Grants: reported, used, revoked from the page, refused.
        val g = Grant.new("app", "Amethyst")
        assertEquals(emptyList<String>(), Device.reportGrants(phone, held, listOf(g)))
        Device.sign(phone, held, 1, "for an app", grant = g.id)
        page(JSONObject().put("call", "revoke").put("session", session).put("grant", g.id))
        assertEquals("revoked", assertThrows(KeykinException::class.java) { Device.sign(phone, held, 1, "again", grant = g.id) }.code)
        assertEquals("revoked", assertThrows(KeykinException::class.java) { Device.nip44Encrypt(phone, held, held.npub, "x", grant = g.id) }.code)
        assertEquals(listOf(g.id), Device.reportGrants(phone, held, listOf(g)))
        Device.sign(phone, held, 1, "my own")

        // Notes: the page asks for a bunker link, this device answers.
        val note = page(JSONObject().put("call", "note_put").put("session", session).put("kind", "bunker").put("text", "")).getString("note")
        val waiting = Device.notes(phone, held)
        assertEquals(listOf(note to "bunker"), waiting.map { it.id to it.kind })
        assertFalse(waiting[0].tap)
        Device.noteDone(phone, held, note, "bunker://abc")
        assertEquals("bunker://abc", page(JSONObject().put("call", "note_get").put("session", session).put("note", note)).getString("result"))

        // A signed-in page asks to add a device: this one does it with no fingerprint.
        val (work, _) = device("Work PC (Kotlin)")
        val inviteNote = page(JSONObject().put("call", "note_put").put("session", session).put("kind", "invite").put("text", Texts.invite(work))).getString("note")
        assertEquals("needs_fingerprint", assertThrows(KeykinException::class.java) { Device.add(phone, held, Texts.readInvite(Texts.invite(work)), { "00".repeat(64) }) }.code)
        Device.add(phone, held, Texts.readInvite(Texts.invite(work)), null, note = inviteNote)
        Device.noteDone(phone, held, inviteNote, Texts.join(held))
        val wh = Device.join(work, Texts.readJoin(Texts.join(held)))
        Device.sign(work, wh, 1, "from the work PC")

        // Hard-to-undo: removing blocked devices is a tap note, and a vanish request needs `tapped`.
        Device.block(phone, held, work.key)
        val cycleNote = page(JSONObject().put("call", "note_put").put("session", session).put("kind", "cycle").put("text", "")).getString("note")
        assertTrue(Device.notes(phone, held).first { it.id == cycleNote }.tap)
        Device.cycle(phone, held, null, note = cycleNote)
        Device.noteDone(phone, held, cycleNote, "ok")
        assertEquals(listOf("Pixel (Kotlin)", "Box"), Device.members(phone, held).map { it.name })
        assertEquals("asks every relay to erase the whole account", Destructive.why(62, listOf(listOf("relay", "ALL_RELAYS")), ""))
        assertNull(Destructive.why(1, emptyList(), "hello"))
        assertEquals("needs_tap", assertThrows(KeykinException::class.java) { Device.sign(phone, held, 62, "", listOf(listOf("relay", "ALL_RELAYS"))) }.code)
        Device.sign(phone, held, 62, "", listOf(listOf("relay", "ALL_RELAYS")), tapped = true)
        // Saying No signs that browser out.
        val again = page(JSONObject().put("call", "note_put").put("session", session).put("kind", "cycle").put("text", "")).getString("note")
        Device.noteRefuse(phone, held, again)
        assertEquals("login", page(JSONObject().put("call", "me").put("session", session)).getString("error"))
    }

    @Test fun bringingInAKeyThePersonAlreadyHas() {
        val text = System.getenv("KEYKIN_BOX_IMPORT") ?: ""
        assumeTrue("set KEYKIN_BOX_IMPORT to a setup text", text.isNotEmpty())
        val nsec = hex(random(32)); val npub = Secp.pub(unhex(nsec))
        assertEquals(nsec, Bech32.decode("nsec", Bech32.nsec(nsec)))
        assertThrows(KeykinException::class.java) { Bech32.decode("nsec", Bech32.npub(nsec)) }
        val (phone, chip) = device("Pixel (Kotlin, import)")
        val held = Device.importKey(phone, Texts.qr(text), nsec)
        assertEquals(npub, held.npub)
        val ev = Device.sign(phone, held, 1, "same identity, now in pieces")
        assertEquals(npub, ev.getString("pubkey"))
        assertTrue(Secp.schnorrVerify(ev.getString("sig"), unhex(ev.getString("id")), npub))
        assertEquals(npub, Secp.pub(unhex(Device.formNsec(phone, held, chip.fp))))
    }

    @Test fun movingTheAccountToAnotherBox() {
        // "<setup text on the old box>|<setup text on the new box>"
        val env = (System.getenv("KEYKIN_BOX_TRANSFER") ?: "").split("|")
        assumeTrue("set KEYKIN_BOX_TRANSFER", env.size == 2)
        val (oldQr, newQr) = Texts.qr(env[0]) to Texts.qr(env[1])
        val (phone, chip) = device("Pixel (Kotlin, moving)")
        val held = Device.create(phone, oldQr)
        val (tablet, _) = device("Tablet (Kotlin, moving)")
        Device.add(phone, held, Texts.readInvite(Texts.invite(tablet)), chip.fp)
        val th = Device.join(tablet, Texts.readJoin(Texts.join(held)))
        val before = Device.formNsec(phone, held, chip.fp)
        var saved = 0; held.changed = { saved++ }

        // The fingerprint is needed, and the box the account is on already is not a new one.
        assertEquals("needs_fingerprint", assertThrows(KeykinException::class.java) { Device.transferToBox(phone, held, newQr, { "00".repeat(64) }) }.code)
        assertEquals("same_box", assertThrows(KeykinException::class.java) { Device.transferToBox(phone, held, Qr(oldQr.addr, oldQr.key, "x"), chip.fp) }.code)
        Device.transferToBox(phone, held, newQr, chip.fp)
        assertEquals(newQr.key, held.boxKey); assertEquals(newQr.addr, held.addr); assertTrue(saved > 0)
        assertEquals(newQr.key, Held.of(held.json()).boxKey)
        val ev = Device.sign(phone, held, 1, "on the new box")
        assertTrue(Secp.schnorrVerify(ev.getString("sig"), unhex(ev.getString("id")), held.npub))
        assertEquals(before, Device.formNsec(phone, held, chip.fp))
        assertEquals(setOf("Pixel (Kotlin, moving)", "Tablet (Kotlin, moving)", "Box"), Device.members(phone, held).map { it.name }.toSet())

        // The tablet is told with a join text, checks the new box, and catches up on its first request there.
        val join = Texts.readJoin(Texts.join(held))
        assertEquals("wrong_account", assertThrows(KeykinException::class.java) { Device.moved(tablet, th, JoinText(join.addr, join.boxKey, "f".repeat(64))) }.code)
        assertEquals("wrong_box", assertThrows(KeykinException::class.java) { Device.moved(tablet, th, JoinText(join.addr, oldQr.key, join.npub)) }.code)
        Device.moved(tablet, th, join)
        assertEquals(newQr.key, th.boxKey)
        val ev2 = Device.sign(tablet, th, 1, "caught up")
        assertTrue(Secp.schnorrVerify(ev2.getString("sig"), unhex(ev2.getString("id")), held.npub))
        assertEquals(held.epoch, th.epoch)
        // The old box's piece no longer fits.
        val stale = Held(th.piece, th.npub, oldQr.key, oldQr.addr, th.epoch)
        assertThrows(KeykinException::class.java) { Device.sign(tablet, stale, 1, "with the old box") }
    }

    @Test fun nostrConnectCodesAndPerSiteLimits() {
        // "<setup text>|<relay url>"
        val env = (System.getenv("KEYKIN_BOX_SITE") ?: "").split("|")
        assumeTrue("set KEYKIN_BOX_SITE", env.size == 2)
        val relay = env[1]
        val (phone, _) = device("Pixel (Kotlin, sites)")
        val held = Device.create(phone, Texts.qr(env[0]))
        val signer = SiteSigner(phone, { held }, { h -> Device.http(h.addr) }, SiteSigner.fresh(), {})

        // Codes that are not right are refused.
        for (bad in listOf("bunker://x", "nostrconnect://nothex?relay=ws%3A%2F%2Fr&secret=1", "nostrconnect://${"a".repeat(64)}?secret=1", "nostrconnect://${"a".repeat(64)}?relay=ws%3A%2F%2Fr"))
            assertEquals(bad, "bad_code", assertThrows(KeykinException::class.java) { Texts.nostrConnect(bad) }.code)

        // The site's side: its own key, listening on the relay for whatever is sent to it.
        val siteSk = random(32); val site = Secp.pub(siteSk)
        val inbox = LinkedBlockingQueue<JSONObject>()
        val ws = okhttp3.OkHttpClient().newWebSocket(okhttp3.Request.Builder().url(relay).build(), object : okhttp3.WebSocketListener() {
            override fun onOpen(w: okhttp3.WebSocket, r: okhttp3.Response) { w.send(JSONArray().put("REQ").put("site").put(JSONObject().put("kinds", JSONArray().put(24133)).put("#p", JSONArray().put(site))).toString()) }
            override fun onMessage(w: okhttp3.WebSocket, text: String) { val m = JSONArray(text); if (m.optString(0) == "EVENT") inbox.put(m.getJSONObject(2)) }
        })
        Thread.sleep(500)
        val code = Texts.nostrConnect("nostrconnect://$site?relay=${java.net.URLEncoder.encode(relay, "UTF-8")}&secret=s3cret&name=Kotlin%20site&url=https%3A%2F%2Fsite.example%2Fapp")
        assertEquals(ConnectCode(site, listOf(relay), "s3cret", "Kotlin site", "https://site.example"), code)
        assertEquals(site, signer.connect("nostrconnect://$site?relay=${java.net.URLEncoder.encode(relay, "UTF-8")}&secret=s3cret&name=Kotlin%20site&url=https%3A%2F%2Fsite.example%2Fapp"))
        val conv = Nip44.conversationKey(Secp.ecdhX(siteSk, signer.pubkey))
        val ack = inbox.poll(10, TimeUnit.SECONDS) ?: error("no answer to the code")
        assertEquals(signer.pubkey, ack.getString("pubkey"))
        assertEquals("s3cret", JSONObject(Nip44.decrypt(ack.getString("content"), conv)).getString("result"))

        fun ask(method: String, vararg params: String): JSONObject {
            val id = hex(random(8)); val at = System.currentTimeMillis() / 1000; val tags = listOf(listOf("p", signer.pubkey))
            val content = Nip44.encrypt(JSONObject().put("id", id).put("method", method).put("params", JSONArray(params.toList())).toString(), conv)
            val eid = eventId(site, at, 24133, tags, content)
            ws.send(JSONArray().put("EVENT").put(JSONObject().put("id", eid).put("pubkey", site).put("created_at", at).put("kind", 24133)
                .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", Secp.schnorrSign(unhex(eid), siteSk))).toString())
            while (true) {
                val ev = inbox.poll(15, TimeUnit.SECONDS) ?: error("no answer to $method")
                val body = JSONObject(Nip44.decrypt(ev.getString("content"), conv))
                if (body.optString("id") == id) return body
            }
        }
        fun post(kind: Int, tags: JSONArray = JSONArray()) = JSONObject().put("kind", kind).put("content", "from a site").put("tags", tags).put("created_at", System.currentTimeMillis() / 1000).toString()
        val signed = JSONObject(ask("sign_event", post(1)).getString("result"))
        assertTrue(Secp.schnorrVerify(signed.getString("sig"), unhex(signed.getString("id")), held.npub))

        // The site is a grant, reported to the box, and the box limits it to posting and then revokes it.
        val g = signer.grants().single()
        assertEquals("https://site.example", g.name)
        assertEquals(emptyList<String>(), Device.reportGrants(phone, held, signer.grants()))
        Device.limit(phone, held, g.id, "posts")
        val follows = JSONArray().put(JSONArray().put("p").put("a".repeat(64)))
        assertEquals("not_allowed", ask("sign_event", post(3, follows)).getString("error"))
        assertEquals("not_allowed", ask("nip44_encrypt", held.npub, "can it read?").getString("error"))
        assertTrue(ask("sign_event", post(7)).has("result"))
        Device.limit(phone, held, g.id, null)
        assertTrue(ask("sign_event", post(3, follows)).has("result"))
        Device.revoke(phone, held, g.id)
        assertEquals("revoked", ask("sign_event", post(1)).getString("error"))
        assertEquals(emptyList<SiteSigner.Site>(), signer.sites())
        assertEquals("not_connected", ask("sign_event", post(1)).getString("error"))
        ws.close(1000, null); signer.stop()
    }

    @Test fun nip44MatchesTheReference() {
        // "<conversation key hex>|<nonce hex>|<plaintext>|<payload>", made by nostr-tools.
        val v = (System.getenv("KEYKIN_NIP44_VECTOR") ?: "").split("|")
        assumeTrue("set KEYKIN_NIP44_VECTOR", v.size == 4)
        assertEquals(v[3], Nip44.encrypt(v[2], unhex(v[0]), unhex(v[1])))
        assertEquals(v[2], Nip44.decrypt(v[3], unhex(v[0])))
        for (n in listOf(1, 31, 32, 33, 64, 65, 255, 257, 1000, 5000)) { val t = "x".repeat(n); assertEquals(t, Nip44.decrypt(Nip44.encrypt(t, unhex(v[0])), unhex(v[0]))) }
        assertThrows(KeykinException::class.java) { Nip44.decrypt(v[3].dropLast(4) + "AAAA", unhex(v[0])) }
    }

    @Test fun helpersAreAskedOnlyWhenTheBoxIsOffAndOnlyToSign() {
        val off: Send = { refuse("no_box") }
        val helper: Send = { JSONObject().put("ok", true).put("by", "helper") }
        val refusing: Send = { JSONObject().put("error", "blocked") }
        fun req(op: String) = JSONObject().put("body", JSONObject().put("op", op))
        assertEquals("helper", Device.withHelpers(off, listOf(helper))(req("sign")).getString("by"))
        assertEquals("helper", Device.withHelpers(off, listOf(refusing, helper))(req("ecdh")).getString("by"))
        assertEquals("blocked", Device.withHelpers(off, listOf(refusing))(req("sign")).getString("error"))
        assertEquals("no_box", assertThrows(KeykinException::class.java) { Device.withHelpers(off, listOf(helper))(req("reveal")) }.code)
        assertEquals("no_box", assertThrows(KeykinException::class.java) { Device.withHelpers(off, emptyList())(req("sign")) }.code)
        assertEquals("box", Device.withHelpers({ JSONObject().put("by", "box") }, listOf(helper))(req("sign")).getString("by"))
    }

    @Test fun bech32MatchesNip19() {
        assertEquals("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg", Bech32.npub("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"))
        assertEquals("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5", Bech32.nsec("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"))
    }
}
