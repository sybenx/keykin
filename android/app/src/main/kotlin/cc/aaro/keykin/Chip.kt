// The chip key (SPEC §4): a P-256 key in the phone's secure hardware that signs only after a
// fingerprint or face check. The box checks its signature on every account change.
package cc.aaro.keykin

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import cc.aaro.keykin.core.Der
import cc.aaro.keykin.core.KeykinException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch

object Chip {
    private const val ALIAS = "keykin-chip"
    private fun ks() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    fun canFingerprint(c: Context) = BiometricManager.from(c).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** Whether the key that exists asks for a fingerprint. False only for the debug stand-in. */
    fun asksFingerprint(c: Context) = c.getSharedPreferences("keykin", 0).getBoolean("chip-auth", false)

    /**
     * The chip key's public half, made on first use. With a fingerprint enrolled, the key needs one for
     * every signature. Without one: no chip key at all, except in a debug build, where a key that asks
     * for nothing stands in so the flows can be tried on an emulator.
     */
    fun publicKey(c: Context): String? {
        if (!ks().containsAlias(ALIAS)) {
            val auth = canFingerprint(c)
            if (!auth && !BuildConfig.DEBUG) return null
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
            if (auth) spec.setUserAuthenticationRequired(true).setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG).setInvalidatedByBiometricEnrollment(true)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec.build()) }.generateKeyPair()
            c.getSharedPreferences("keykin", 0).edit().putBoolean("chip-auth", auth).apply()
        }
        return Der.compressed(ks().getCertificate(ALIAS).publicKey as ECPublicKey)
    }

    /**
     * Signs `message` after showing the fingerprint prompt. Call from a background thread: it waits for
     * the person. Throws `cancelled` if they back out, `fingerprint_changed` if a new finger was enrolled.
     */
    fun sign(a: FragmentActivity, title: String, message: ByteArray): String {
        val sig = try { Signature.getInstance("SHA256withECDSA").apply { initSign(ks().getKey(ALIAS, null) as PrivateKey) } }
            catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) { throw KeykinException("fingerprint_changed") }
        if (!asksFingerprint(a)) return Der.toCompact(sig.apply { update(message) }.sign())
        val done = CountDownLatch(1)
        var out: String? = null; var why = "cancelled"
        a.runOnUiThread {
            BiometricPrompt(a, ContextCompat.getMainExecutor(a), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    try { out = Der.toCompact(r.cryptoObject!!.signature!!.apply { update(message) }.sign()) } catch (_: Exception) { why = "failed" }
                    done.countDown()
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) { done.countDown() }
            }).authenticate(
                BiometricPrompt.PromptInfo.Builder().setTitle(title).setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel").build(),
                BiometricPrompt.CryptoObject(sig))
        }
        done.await()
        return out ?: throw KeykinException(why)
    }
}
