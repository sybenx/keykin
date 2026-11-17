// The Kotlin device against a real box (the TypeScript one). Give the box's setup text in KEYKIN_BOX_QR;
// without it these tests are skipped. A software P-256 key stands in for the phone's chip.
package cc.aaro.keykin

import cc.aaro.keykin.core.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

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
