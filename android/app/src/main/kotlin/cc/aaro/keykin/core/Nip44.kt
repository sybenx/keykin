// NIP-44 version 2: the message encryption Nostr apps use. Given a conversation key, this is ChaCha20
// with a padded plaintext and an HMAC-SHA256 over nonce and ciphertext. How the conversation key is made
// from two pieces is in Device.conversationKey.
package cc.aaro.keykin.core

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec

object Nip44 {
    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); parts.forEach(::update); doFinal() }
    /** HKDF-extract with the salt "nip44-v2" over the shared x. */
    fun conversationKey(sharedX: ByteArray): ByteArray = hmac(utf8("nip44-v2"), sharedX)
    private fun expand(prk: ByteArray, info: ByteArray, len: Int): ByteArray {
        var t = ByteArray(0); var out = ByteArray(0); var n = 1
        while (out.size < len) { t = hmac(prk, t, info, byteArrayOf(n.toByte())); out += t; n++ }
        return out.copyOf(len)
    }
    private fun paddedLen(len: Int): Int {
        if (len <= 32) return 32
        val next = Integer.highestOneBit(len - 1) shl 1
        val chunk = if (next <= 256) 32 else next / 8
        return chunk * ((len - 1) / chunk + 1)
    }
    private fun chacha(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("ChaCha20").run { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), ChaCha20ParameterSpec(nonce, 0)); doFinal(data) }

    fun encrypt(text: String, convKey: ByteArray, nonce: ByteArray = random(32)): String {
        val plain = utf8(text)
        if (plain.isEmpty() || plain.size > 65535) refuse("bad_message")
        val keys = expand(convKey, nonce, 76)
        val padded = ByteArray(2 + paddedLen(plain.size)).also { it[0] = (plain.size ushr 8).toByte(); it[1] = plain.size.toByte(); plain.copyInto(it, 2) }
        val ct = chacha(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), padded)
        return Base64.getEncoder().encodeToString(byteArrayOf(2) + nonce + ct + hmac(keys.copyOfRange(44, 76), nonce, ct))
    }
    fun decrypt(payload: String, convKey: ByteArray): String {
        val b = try { Base64.getDecoder().decode(payload) } catch (_: Exception) { refuse("bad_message") }
        if (b.size < 99 || b[0].toInt() != 2) refuse("bad_message")
        val nonce = b.copyOfRange(1, 33); val ct = b.copyOfRange(33, b.size - 32); val mac = b.copyOfRange(b.size - 32, b.size)
        val keys = expand(convKey, nonce, 76)
        if (!java.security.MessageDigest.isEqual(mac, hmac(keys.copyOfRange(44, 76), nonce, ct))) refuse("bad_message")
        val padded = chacha(keys.copyOfRange(0, 32), keys.copyOfRange(32, 44), ct)
        val len = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        if (len == 0 || padded.size != 2 + paddedLen(len)) refuse("bad_message")
        return String(padded, 2, len, Charsets.UTF_8)
    }
}

/** bech32 (NIP-19) for showing keys the way Nostr apps do: `npub1…` and `nsec1…`. */
object Bech32 {
    private const val CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private fun polymod(v: List<Int>): Int {
        var chk = 1
        for (x in v) { val b = chk ushr 25; chk = ((chk and 0x1ffffff) shl 5) xor x
            for ((i, g) in intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3).withIndex()) if ((b ushr i) and 1 == 1) chk = chk xor g }
        return chk
    }
    fun encode(hrp: String, data: ByteArray): String {
        val five = ArrayList<Int>(); var acc = 0; var bits = 0
        for (b in data) { acc = (acc shl 8) or (b.toInt() and 0xff); bits += 8; while (bits >= 5) { bits -= 5; five.add((acc ushr bits) and 31) } }
        if (bits > 0) five.add((acc shl (5 - bits)) and 31)
        val exp = hrp.map { it.code ushr 5 } + 0 + hrp.map { it.code and 31 }
        val mod = polymod(exp + five + List(6) { 0 }) xor 1
        return hrp + "1" + (five + List(6) { (mod ushr (5 * (5 - it))) and 31 }).joinToString("") { CHARS[it].toString() }
    }
    fun npub(hexKey: String) = encode("npub", unhex(hexKey))
    fun nsec(hexKey: String) = encode("nsec", unhex(hexKey))
}
