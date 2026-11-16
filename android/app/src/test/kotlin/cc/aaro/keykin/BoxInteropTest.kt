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
    }
}
