// What this device keeps: its member key, its name and, once in an account, its piece. One file in the
// app's private no-backup folder, encrypted with a key that never leaves the phone's Keystore.
package cc.aaro.keykin

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import cc.aaro.keykin.core.Held
import cc.aaro.keykin.core.Me
import cc.aaro.keykin.core.hex
import cc.aaro.keykin.core.random
import cc.aaro.keykin.core.unhex
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class Store(private val c: Context) {
    private val file = File(c.noBackupFilesDir, "device.bin")
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey("keykin-store", null) as SecretKey?)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("keykin-store", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        }.generateKey()
    }
    @Synchronized private fun read(): JSONObject? {
        if (!file.exists()) return null
        val b = file.readBytes()
        val plain = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, 12)) }.doFinal(b, 12, b.size - 12)
        return JSONObject(String(plain, Charsets.UTF_8))
    }
    @Synchronized private fun write(o: JSONObject) {
        val ci = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(ci.iv + ci.doFinal(o.toString().toByteArray(Charsets.UTF_8)))
        tmp.renameTo(file)
    }

    /** This device, made on first use. */
    fun me(name: String): Me {
        val o = read() ?: JSONObject().put("sk", hex(random(32))).put("name", name).also(::write)
        return Me(unhex(o.getString("sk")), o.getString("name"), Chip.publicKey(c))
    }
    fun held(): Held? = read()?.optJSONObject("held")?.let(Held::of)
    /** The site signer's saved state: its own key, the sites signed in, and tickets waiting. */
    @Synchronized fun signerState(): org.json.JSONObject = read()?.optJSONObject("signer") ?: cc.aaro.keykin.core.SiteSigner.fresh().also { keepSigner(it) }
    @Synchronized fun keepSigner(st: org.json.JSONObject) { read()?.let { write(it.put("signer", st)) } }
    /** Where other devices listen, as last seen at the box: used when the box is off. */
    fun helpers(): List<String> = read()?.optJSONArray("helpers")?.let { a -> List(a.length()) { a.getString(it) } } ?: emptyList()
    @Synchronized fun keepHelpers(addrs: List<String>) { read()?.let { write(it.put("helpers", org.json.JSONArray(addrs))) } }
    /** The box, then the helpers. */
    fun send(h: Held): cc.aaro.keykin.core.Send = cc.aaro.keykin.core.Device.withHelpers(cc.aaro.keykin.core.Device.http(h.addr), helpers().map { cc.aaro.keykin.core.Device.http(it) })
    /** Forgets the account on this phone: its piece goes. The phone's own key and name stay. */
    @Synchronized fun forget() { read()?.let { it.remove("held"); it.remove("helpers"); write(it) } }
    @Synchronized fun keep(h: Held) { write((read() ?: error("no device")).put("held", h.json())) }
}
