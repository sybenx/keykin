// Signing for other apps on the phone (NIP-55). Apps ask through a `nostrsigner:` screen, or silently
// through the content provider once the person chose "Always allow" for that app. Tier 2: an allowed
// app's requests are answered with no prompt. Every answer still needs the box, so a blocked phone
// answers nothing.
package cc.aaro.keykin

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import cc.aaro.keykin.core.Device
import cc.aaro.keykin.core.KeykinException
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread

/** The apps the person chose "Always allow" for. */
object Apps {
    private fun prefs(c: Context) = c.getSharedPreferences("keykin-apps", 0)
    fun allowed(c: Context, pkg: String?) = pkg != null && prefs(c).getBoolean(pkg, false)
    fun allow(c: Context, pkg: String) = prefs(c).edit().putBoolean(pkg, true).apply()
    fun signOut(c: Context, pkg: String) = prefs(c).edit().remove(pkg).apply()
    fun all(c: Context): List<String> = prefs(c).all.keys.sorted()
    fun label(c: Context, pkg: String?): String = if (pkg == null) "An app" else try { c.packageManager.getApplicationLabel(c.packageManager.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg }
}

object Signer {
    val TYPES = setOf("get_public_key", "sign_event", "nip44_encrypt", "nip44_decrypt")

    /** Does what was asked and returns the answer's fields, or throws. */
    fun answer(c: Context, type: String, payload: String, peer: String): Map<String, String> {
        val store = Store(c)
        val me = store.me(Build.MODEL ?: "Android device")
        val h = store.held() ?: throw KeykinException("no_account")
        h.changed = { store.keep(it) }
        return when (type) {
            "get_public_key" -> mapOf("result" to h.npub, "package" to c.packageName)
            "sign_event" -> {
                val e = JSONObject(payload)
                val tags = (e.optJSONArray("tags") ?: JSONArray()).let { a -> List(a.length()) { i -> a.getJSONArray(i).let { t -> List(t.length()) { t.getString(it) } } } }
                val ev = Device.sign(me, h, e.getInt("kind"), e.optString("content", ""), tags, if (e.has("created_at")) e.getLong("created_at") else System.currentTimeMillis() / 1000)
                mapOf("result" to ev.getString("sig"), "signature" to ev.getString("sig"), "event" to ev.toString())
            }
            "nip44_encrypt" -> mapOf("result" to Device.nip44Encrypt(me, h, peer, payload), "signature" to "")
            "nip44_decrypt" -> mapOf("result" to Device.nip44Decrypt(me, h, peer, payload), "signature" to "")
            else -> throw KeykinException("unsupported")
        }.let { if (type.startsWith("nip44")) mapOf("result" to it.getValue("result"), "signature" to it.getValue("result")) else it }
    }

    /** What is being asked, in a sentence. */
    fun describe(app: String, type: String, payload: String): String = app + when (type) {
        "get_public_key" -> " wants to sign in with your account."
        "sign_event" -> " wants to sign: " + (try { JSONObject(payload).let { "kind ${it.opt("kind")}. " + it.optString("content").take(140) } } catch (_: Exception) { "an event." })
        "nip44_encrypt" -> " wants to encrypt a message as you."
        "nip44_decrypt" -> " wants to read an encrypted message."
        else -> " asks for something Keykin does not do ($type)."
    }
}

/** The screen an app opens to ask (the `nostrsigner:` scheme). */
class SignerActivity : FragmentActivity() {
    private var busy by mutableStateOf(false)
    private var problem by mutableStateOf<String?>(null)

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val type = intent.getStringExtra("type") ?: "get_public_key"
        var payload = intent.dataString?.removePrefix("nostrsigner:") ?: ""
        if (payload.startsWith("%7B", ignoreCase = true)) payload = java.net.URLDecoder.decode(payload, "UTF-8")   // some apps encode the JSON
        val peer = intent.getStringExtra("pubkey") ?: ""
        val id = intent.getStringExtra("id")
        val pkg = callingPackage
        val app = Apps.label(this, pkg)

        fun deny() { setResult(RESULT_CANCELED, Intent().putExtra("rejected", true).also { i -> id?.let { i.putExtra("id", it) } }); finish() }
        fun allow(always: Boolean) {
            if (busy) return
            busy = true; problem = null
            thread {
                try {
                    val out = Signer.answer(this, type, payload, peer)
                    if (always && pkg != null) Apps.allow(this, pkg)
                    if (BuildConfig.DEBUG) android.util.Log.i("Keykin", "nip55 $type ok " + out.getValue("result").take(16))
                    runOnUiThread { setResult(RESULT_OK, Intent().also { i -> out.forEach { (k, v) -> i.putExtra(k, v) }; id?.let { i.putExtra("id", it) } }); finish() }
                } catch (e: Exception) {
                    problem = when ((e as? KeykinException)?.code) { "blocked" -> "This device is blocked."; "no_box" -> "Cannot reach the box."; "no_account" -> "Keykin has no account on this phone yet."; else -> "That did not work." }
                    busy = false
                }
            }
        }
        if (type !in Signer.TYPES) return deny()
        if (Apps.allowed(this, pkg)) allow(false)

        setContent {
            val p = palette()
            Column(Modifier.fillMaxSize().background(p.bg).systemBarsPadding().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Title("Keykin")
                Card {
                    Head(Signer.describe(app, type, payload))
                    problem?.let { Warn(it) }
                    if (busy) Dim("Working…")
                    Btn("Allow once", Kind.Main, !busy, Modifier.fillMaxWidth()) { allow(false) }
                    if (pkg != null) Btn("Always allow $app", enabled = !busy, modifier = Modifier.fillMaxWidth()) { allow(true) }
                    Btn("Deny", Kind.Danger, !busy, Modifier.fillMaxWidth()) { deny() }
                }
            }
        }
    }
}

/** The silent path: an app the person always allows asks here and gets an answer without a screen. */
class SignerProvider : ContentProvider() {
    override fun onCreate() = true
    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val c = context ?: return null
        val type = uri.authority?.substringAfterLast('.')?.lowercase() ?: return null
        if (type !in Signer.TYPES || !Apps.allowed(c, callingPackage)) return null          // null: the app opens the screen instead
        val args = projection?.takeIf { it.isNotEmpty() } ?: selectionArgs ?: return null     // [payload, pubkey, current_user]
        return try {
            val out = Signer.answer(c, type, args.getOrNull(0) ?: "", args.getOrNull(1) ?: "")
            MatrixCursor(out.keys.toTypedArray()).apply { addRow(out.values.toTypedArray()) }
        } catch (_: Exception) { null }
    }
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?) = 0
}
