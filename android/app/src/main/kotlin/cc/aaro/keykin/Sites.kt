// Signing in to a site by scanning its code (QRST signer-ticket), on the phone. One signer for the
// whole app, alive while the app's process is: it listens on the relays its sites and tickets name.
package cc.aaro.keykin

import android.content.Context
import android.os.Build
import cc.aaro.keykin.core.KeykinException
import cc.aaro.keykin.core.SiteSigner
import cc.aaro.qrst.core.CodeCheck
import cc.aaro.qrst.core.Env
import cc.aaro.qrst.core.Mode
import cc.aaro.qrst.core.PairingParams
import cc.aaro.qrst.core.PairingUri
import cc.aaro.qrst.core.Phase
import cc.aaro.qrst.core.SignerTicket
import cc.aaro.qrst.core.SignerTicketProfile
import cc.aaro.qrst.net.MemoryKeyValue
import cc.aaro.qrst.net.Transfer
import cc.aaro.qrst.net.TransferDeps
import cc.aaro.qrst.net.TransferView
import java.security.SecureRandom

object Sites {
    @Volatile private var signer: SiteSigner? = null

    /** The signer, made on first use and started if it has anything to listen for. */
    @Synchronized fun signer(c: Context): SiteSigner {
        signer?.let { return it }
        val app = c.applicationContext
        val store = Store(app)
        val me = store.me(Build.MODEL ?: "Android device")
        return SiteSigner(me, { store.held()?.also { h -> h.changed = { store.keep(it) } } }, { h -> store.send(h) }, store.signerState(), { store.keepSigner(it) },
            { if (BuildConfig.DEBUG) android.util.Log.i("Keykin", it) }).also { signer = it; it.start() }
    }

    /** A site's sign-in code, or null if the text is something else. */
    fun read(text: String): PairingParams? {
        if (BuildConfig.DEBUG) PairingUri.allowLoopback = true      // an emulator's relay is on this machine
        val p = try { PairingUri.parse(text) } catch (_: Exception) { return null }
        return p.takeIf { it.profile == SignerTicketProfile.id && it.mode == Mode.OFFER }
    }

    private val env = object : Env {
        private val rnd = SecureRandom()
        override fun random(length: Int) = ByteArray(length).also(rnd::nextBytes)
        override fun now() = System.currentTimeMillis() / 1000
    }
    private fun until(t: Transfer<SignerTicket>, ms: Long, pred: (TransferView<SignerTicket>) -> Boolean): TransferView<SignerTicket> {
        val end = System.currentTimeMillis() + ms
        while (true) { val v = t.view(); if (pred(v)) return v; if (System.currentTimeMillis() > end) throw KeykinException("site_silent"); Thread.sleep(80) }
    }

    /**
     * Answers a site's code, after the person said yes. `sameDigits` is asked when this phone's own camera
     * did not read the code: it shows five digits and returns whether the site shows the same. Blocks; call
     * off the main thread. The ticket is made only at the moment it is released.
     */
    fun answer(c: Context, params: PairingParams, viaCamera: Boolean, sameDigits: (String) -> Boolean) {
        val s = signer(c)
        val deps = TransferDeps(SignerTicketProfile, cc.aaro.qrst.net.Store(MemoryKeyValue()), env, "https://keykin.invalid/", if (viaCamera) CodeCheck.NONE else CodeCheck.COMPARE)
        val t = Transfer.join(deps, params, viaCamera)
        try {
            val v = until(t, 60_000) { it.session.phase == Phase.RELEASE || it.stage == TransferView.Stage.ENDED }
            if (v.stage == TransferView.Stage.ENDED) throw KeykinException("site_silent")
            fun ticket() = s.mint(params.origin, params.relays).let { j ->
                SignerTicket(j.getString("pubkey"), j.getString("signer"), params.relays, j.getString("t"), j.getLong("expires"))
            }
            when (v.session.check) {
                CodeCheck.NONE -> t.release(ticket())
                CodeCheck.COMPARE -> if (sameDigits(v.session.compare ?: throw KeykinException("site_silent"))) t.confirmMatch(ticket()) else { t.rejectMatch(); throw KeykinException("digits_differ") }
                else -> throw KeykinException("site_wants_typing")
            }
            val end = until(t, 60_000) { it.stage == TransferView.Stage.ENDED }
            if (end.session.outcome?.wire != "delivered") throw KeykinException("site_declined")
        } finally { t.dispose() }
    }
}
