// Keykin's one activity. A handful of screens: start, join, home with the device list, and the codes
// shown to other devices. Work with the box runs on a background thread; the fingerprint prompt appears
// from there when an account change needs it.
package cc.aaro.keykin

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import cc.aaro.keykin.core.*
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlin.concurrent.thread

sealed interface Screen {
    data object Start : Screen
    data object Home : Screen
    data object Invite : Screen                       // this new device shows its invite
    data object Import : Screen                       // bring in a key the person already has
    data class Paste(val back: Screen) : Screen
    data class JoinCode(val text: String, val name: String) : Screen   // shown to the device just added
    data class Nsec(val nsec: String) : Screen
    data class SiteAsk(val params: cc.aaro.qrst.core.PairingParams, val viaCamera: Boolean) : Screen   // a site's sign-in code was read
    data class SiteDigits(val digits: String, val origin: String) : Screen
}

class MainActivity : FragmentActivity() {
    private lateinit var store: Store
    private lateinit var me: Me
    private var held by mutableStateOf<Held?>(null)
    private var screen by mutableStateOf<Screen>(Screen.Start)
    private var members by mutableStateOf<List<Member>>(emptyList())
    private var busy by mutableStateOf(false)
    private var note by mutableStateOf<String?>(null)
    private var problem by mutableStateOf<String?>(null)
    /** A key typed in on the import screen, waiting for the box's code. Never saved. */
    private var pendingNsec: String? = null
    /** Whether this phone still holds the whole key as a backup (after an import). */
    private var keptKey by mutableStateOf(false)
    private var apps by mutableStateOf<List<String>>(emptyList())
    private fun own(h: Held): Held { h.changed = { store.keep(it) }; store.keep(h); held = h; return h }
    override fun onResume() { super.onResume(); if (::store.isInitialized) apps = Apps.all(this) }

    private var sites by mutableStateOf<List<cc.aaro.keykin.core.SiteSigner.Site>>(emptyList())
    private var digitsAnswer: java.util.concurrent.SynchronousQueue<Boolean>? = null
    private val scanner = registerForActivityResult(ScanContract()) { r -> r.contents?.let { handleText(it, viaCamera = true) } }
    private fun scan(prompt: String) = scanner.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt(prompt).setBeepEnabled(false).setOrientationLocked(false))

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        store = Store(this)
        me = store.me(Build.MODEL ?: "Android device")
        held = store.held()?.also { it.changed = { h -> store.keep(h) } }
        apps = Apps.all(this)
        keptKey = store.nsec() != null
        screen = if (held != null) Screen.Home else Screen.Start
        if (held != null) { refresh(); refreshSites() }
        // Dark icons on the light background and the reverse, so the status bar stays readable.
        val dark = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) == android.content.res.Configuration.UI_MODE_NIGHT_YES
        androidx.core.view.WindowCompat.getInsetsController(window, window.decorView).apply { isAppearanceLightStatusBars = !dark; isAppearanceLightNavigationBars = !dark }
        setContent { App() }
        debugText(intent)
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); debugText(intent) }
    // A debug build can be handed a code as text (base64), for an emulator with no camera to point at a screen.
    private fun debugText(i: Intent?) {
        if (!BuildConfig.DEBUG) return
        i?.getStringExtra("text64")?.let { handleText(String(Base64.decode(it, Base64.DEFAULT), Charsets.UTF_8)) }
        when (i?.getStringExtra("do")) { "sign" -> signTest(); "nsec" -> showNsec(); "invite" -> screen = Screen.Invite; "cycle" -> cycle() }
        i?.getStringExtra("nip44")?.let { v -> val p = v.split("|"); try { android.util.Log.i("Keykin", "nip44 check: " + Nip44.decrypt(p[1], unhex(p[0]))) } catch (e: Throwable) { android.util.Log.i("Keykin", "nip44 check failed: " + e.javaClass.name + " " + e.message) } }
        i?.getStringExtra("grant")?.let { Apps.allow(this, it); apps = Apps.all(this) }
        i?.getStringExtra("block")?.let { n -> members.firstOrNull { it.name == n }?.let(::toggleBlock) }
    }

    private fun say(code: String) = when (code) {
        "no_box" -> "Cannot reach the box."
        "bad_code" -> "That code is no longer valid. Reload the box's page and scan again."
        "already_set_up" -> "That box already has an account."
        "blocked" -> "This device is blocked."
        "no_chip_key" -> "This device has no fingerprint set up, so it cannot do that."
        "needs_fingerprint" -> "The box did not accept the fingerprint."
        "fingerprint_changed" -> "The fingerprints on this phone changed. This device has to be added again."
        "cancelled" -> "Cancelled."
        "not_ready", "no_welcome" -> "The other device has not finished adding this one yet."
        "bad_qr", "bad_invite", "bad_join" -> "That is not a Keykin code."
        "bad_key" -> "That is not an nsec."
        "already_here" -> "That key already has an account on this box."
        "unknown_account", "unknown_member" -> "The box does not know this account any more. Forget it on this phone and start again."
        "wrong_box" -> "That code is from a different box."
        "site_silent" -> "The site did not answer. Show its code again and retry."
        "site_declined" -> "The site did not take the sign-in."
        "digits_differ" -> "The digits differed, so nothing was sent."
        "site_wants_typing" -> "That site asks for the digits to be typed, which Keykin does not do yet."
        "pending_welcome" -> "A device you added has not finished joining yet. Finish that first."
        else -> "That did not work ($code)."
    }
    /** Runs `work` off the main thread, showing what went wrong in plain words. */
    private fun work(work: () -> Unit) {
        if (busy) return
        busy = true; problem = null; note = null
        thread {
            try { work() } catch (e: KeykinException) { problem = say(e.code) } catch (e: Exception) { problem = "That did not work (${e.javaClass.simpleName})." }
            busy = false
        }
    }
    private fun fingerprint(title: String): Fingerprint = { m -> Chip.sign(this, title, m) }

    /** Any Keykin code, scanned or pasted: the box's setup code, another device's invite, or a join code. */
    private fun handleText(text: String, viaCamera: Boolean = false) {
        val t = text.trim()
        val site = Sites.read(t)
        when {
            site != null -> if (held != null) screen = Screen.SiteAsk(site, viaCamera) else problem = "Add this device to an account first."
            t.contains("\"invite\"") -> held?.let { h -> work {
                val inv = Texts.readInvite(t)
                Device.add(me, h, inv, fingerprint("Add ${inv.name}"))
                screen = Screen.JoinCode(Texts.join(h), inv.name); loadMembers()
            } } ?: run { problem = "Add this device to an account first." }
            t.contains("\"login\"") -> held?.let { h -> work {
                Device.approveLogin(me, h, t, fingerprint("Log in to the box's page")); note = "That browser is logged in to the box."
            } } ?: run { problem = "Add this device to an account first." }
            t.contains("\"join\"") -> work { own(Device.join(me, Texts.readJoin(t))); screen = Screen.Home; loadMembers() }
            else -> work {
                if (held != null) refuse("already_set_up")
                val nsec = pendingNsec
                if (nsec != null) {
                    own(Device.importKey(me, Texts.qr(t), nsec)); store.keepNsec(nsec); keptKey = true; pendingNsec = null
                    screen = Screen.Home; loadMembers(); note = "Done. Signing now uses the pieces. This phone still holds the whole key as a backup, until you choose to forget it."
                    return@work
                }
                own(Device.create(me, Texts.qr(t))); screen = Screen.Home; loadMembers()
            }
        }
    }
    private fun loadMembers() { held?.let { members = Device.members(me, it); store.keepHelpers(members.filter { m -> m.addr != null && !m.blocked && m.key != me.key }.map { m -> m.addr!! }) } }
    private fun refresh() = work { loadMembers() }
    private fun toggleBlock(m: Member) = held?.let { h -> work {
        if (m.blocked) Device.unblock(me, h, m.key, fingerprint("Unblock ${m.name}")) else Device.block(me, h, m.key)
        loadMembers(); note = if (m.blocked) "${m.name} is unblocked." else "${m.name} is blocked."
    } }
    private fun signTest() = held?.let { h -> work {
        val ev = Device.sign(me, h, 1, "Signed by Keykin on ${me.name}", send = store.send(h))
        note = "Signed. Event ${ev.getString("id").take(12)}…"
        android.util.Log.i("Keykin", "signed " + ev.getString("id"))
    } }
    private fun refreshSites() { if (held != null) sites = Sites.signer(this).sites() }
    /** The person said yes to a site: hand it a ticket. If the camera did not read the code, the digits are compared first. */
    private fun allowSite(a: Screen.SiteAsk) = work {
        val origin = a.params.origin ?: "that site"
        screen = Screen.Home
        note = "Reaching $origin…"
        Sites.answer(this, a.params, a.viaCamera) { digits ->
            val q = java.util.concurrent.SynchronousQueue<Boolean>(); digitsAnswer = q
            screen = Screen.SiteDigits(digits, origin)
            q.take().also { screen = Screen.Home }
        }
        refreshSites(); note = "$origin can now sign as you."
    }
    private fun cycle() = held?.let { h -> work {
        Device.cycle(me, h, fingerprint("Remove blocked devices for good")); loadMembers(); note = "Done. Blocked devices are gone for good."
    } }
    // Showing the kept key asks for the fingerprint first, when this phone has one.
    private fun showKept() = work {
        val k = store.nsec() ?: refuse("no_key")
        if (me.chip != null) Chip.sign(this, "Show the whole key", utf8("keykin-show-key"))
        screen = Screen.Nsec(k)
    }
    private fun showNsec() = held?.let { h -> work { screen = Screen.Nsec(Device.formNsec(me, h, fingerprint("Form the whole key on this device"))) } }
    private fun copy(text: String) { (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("Keykin", text)) }

    @Composable private fun App() {
        val p = palette()
        Column(Modifier.fillMaxSize().background(p.bg).systemBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Title("Keykin")
            problem?.let { Warn(it) }
            note?.let { Dim(it) }
            if (busy) Dim("Working…")
            when (val s = screen) {
                Screen.Start -> Start()
                Screen.Home -> Home()
                Screen.Invite -> InviteScreen()
                Screen.Import -> ImportScreen()
                is Screen.Paste -> PasteScreen(s)
                is Screen.JoinCode -> JoinCodeScreen(s)
                is Screen.Nsec -> NsecScreen(s)
                is Screen.SiteAsk -> SiteAskScreen(s)
                is Screen.SiteDigits -> SiteDigitsScreen(s)
            }
        }
    }

    @Composable private fun Start() {
        Card {
            Head("Start with your box")
            Dim("Open the box's page and scan the code it shows. This phone and the box make your key together. The whole key never exists on either.")
            Btn("Scan the box's code", Kind.Main, !busy, Modifier.fillMaxWidth()) { scan("Scan the code on the box's page") }
            Btn("Paste the code instead", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Paste(Screen.Start) }
        }
        Card {
            Head("Already have an account?")
            Dim("Add this phone from a device that is already in it.")
            Btn("Add this phone", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Invite }
        }
        Card {
            Head("Use a key you already have")
            Dim("Bring your nsec in. This phone splits it with the box, and keeps the whole key as a backup until you choose to forget it.")
            Btn("Bring in my nsec", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Import }
        }
        if (me.chip == null) Dim("This phone has no fingerprint or face set up. It will be able to sign, but not to add devices, unblock them or form the whole key.")
    }

    @Composable private fun ImportScreen() {
        BackHandler { pendingNsec = null; screen = Screen.Start }
        var text by remember { mutableStateOf("") }
        var ready by remember { mutableStateOf(false) }
        val p = palette()
        Card {
            Head("1. Your nsec")
            Dim("Paste the key that starts with nsec1. This phone keeps it, encrypted, as a backup. Forgetting it is your choice, later.")
            BasicTextField(text, { text = it; ready = false }, Modifier.fillMaxWidth().heightIn(min = 72.dp).background(p.bg, RoundedCornerShape(8.dp)).border(1.dp, p.line, RoundedCornerShape(8.dp)).padding(12.dp),
                textStyle = TextStyle(color = p.text, fontSize = 14.sp), cursorBrush = SolidColor(p.accent))
            Btn("Use this key", Kind.Main, !busy && text.isNotBlank(), Modifier.fillMaxWidth()) {
                try {
                    val t = text.trim()
                    pendingNsec = if (t.startsWith("nsec1")) Bech32.decode("nsec", t) else t.lowercase().also { if (!Regex("^[0-9a-f]{64}$").matches(it)) refuse("bad_key") }
                    text = ""; ready = true; problem = null
                } catch (_: KeykinException) { problem = "That is not an nsec." }
            }
        }
        if (ready) Card {
            Head("2. Scan the box's code")
            Dim("Open the box's admin page and scan the setup code it shows.")
            Btn("Scan the box's code", Kind.Main, !busy, Modifier.fillMaxWidth()) { scan("Scan the code on the box's page") }
            Btn("Paste the code instead", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Paste(Screen.Import) }
        }
    }

    @Composable private fun InviteScreen() {
        BackHandler { screen = Screen.Start }
        Card {
            Head("1. Show this to a device in your account")
            Dim("On that device, choose Add a device and scan this.")
            QrImage(Texts.invite(me), "This phone's invite code")
            Btn("Copy as text", modifier = Modifier.fillMaxWidth()) { copy(Texts.invite(me)); note = "Copied." }
        }
        Card {
            Head("2. Then scan the code it shows")
            Btn("Scan the join code", Kind.Main, !busy, Modifier.fillMaxWidth()) { scan("Scan the join code on the other device") }
            Btn("Paste the code instead", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Paste(Screen.Invite) }
        }
    }

    @Composable private fun PasteScreen(s: Screen.Paste) {
        BackHandler { screen = s.back }
        var text by remember { mutableStateOf("") }
        val p = palette()
        Card {
            Head("Paste a Keykin code")
            BasicTextField(text, { text = it }, Modifier.fillMaxWidth().heightIn(min = 120.dp).background(p.bg, RoundedCornerShape(8.dp)).border(1.dp, p.line, RoundedCornerShape(8.dp)).padding(12.dp),
                textStyle = TextStyle(color = p.text, fontSize = 14.sp), cursorBrush = SolidColor(p.accent))
            Btn("Continue", Kind.Main, !busy && text.isNotBlank(), Modifier.fillMaxWidth()) { screen = s.back; handleText(text) }
            Btn("Back", modifier = Modifier.fillMaxWidth()) { screen = s.back }
        }
    }

    @Composable private fun Home() {
        val h = held ?: return
        Card {
            Head("Your account")
            Mono(Bech32.npub(h.npub))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Btn("Sign a test note", enabled = !busy) { signTest() }
                Btn("Refresh", enabled = !busy) { refresh() }
            }
        }
        Card {
            Head("Devices")
            for (m in members) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Body(m.name + when { m.key == me.key -> "  (this phone)"; m.kind == "box" -> "  (box)"; else -> "" })
                        if (m.blocked) Warn("Blocked") else if (m.kind == "device" && !m.chip) Dim("No fingerprint key")
                    }
                    if (m.kind == "device" && m.key != me.key) Btn(if (m.blocked) "Unblock" else "Block", if (m.blocked) Kind.Plain else Kind.Danger, !busy) { toggleBlock(m) }
                }
            }
            if (members.any { it.blocked }) {
                Dim("A blocked device still holds its old piece. Removing it makes that piece useless and takes it off the list.")
                Btn("Remove blocked devices for good", Kind.Danger, !busy, Modifier.fillMaxWidth()) { cycle() }
            }
            Btn("Add a device", Kind.Main, !busy, Modifier.fillMaxWidth()) { scan("Scan the invite code on the new device") }
            Btn("Paste an invite instead", enabled = !busy, modifier = Modifier.fillMaxWidth()) { screen = Screen.Paste(Screen.Home) }
        }
        Card {
            Head("The box's page")
            Dim("To log a browser in to the box's page, scan the code that page shows.")
            Btn("Scan the page's code", enabled = !busy, modifier = Modifier.fillMaxWidth()) { scan("Scan the code on the box's page") }
        }
        Card {
            Head("Sites")
            Dim("To sign in to a site that shows a code, scan it.")
            for (site in sites) Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Body(site.origin ?: (site.key.take(12) + "…"), Modifier.weight(1f))
                Btn("Sign out", enabled = !busy) { Sites.signer(this@MainActivity).signOut(site.key); refreshSites() }
            }
            Btn("Scan a site's code", enabled = !busy, modifier = Modifier.fillMaxWidth()) { scan("Scan the code the site shows") }
        }
        if (apps.isNotEmpty()) Card {
            Head("Apps that sign with this account")
            for (pkg in apps) Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Body(Apps.label(this@MainActivity, pkg), Modifier.weight(1f))
                Btn("Sign out", enabled = !busy) { Apps.signOut(this@MainActivity, pkg); apps = Apps.all(this@MainActivity) }
            }
        }
        Card {
            var sure by remember { mutableStateOf(false) }
            Head("This phone")
            Dim("Forgetting the account here removes this phone's piece. The account itself is untouched. Without another device that can sign with the box, it cannot be used again.")
            if (!sure) Btn("Forget the account on this phone", Kind.Danger, !busy, Modifier.fillMaxWidth()) { sure = true }
            else Btn("Yes, forget it", Kind.Danger, !busy, Modifier.fillMaxWidth()) { store.forget(); held = null; members = emptyList(); sure = false; screen = Screen.Start; note = "This phone has no account now." }
        }
        if (keptKey) Card {
            var sure by remember { mutableStateOf(false) }
            Head("Backup: the whole key is on this phone")
            Dim("You brought this key in, so this phone still holds all of it, encrypted. It is how the account comes back if the pieces are lost, and it can be moved to another device. Forgetting it is up to you.")
            Btn("Show the whole key", enabled = !busy, modifier = Modifier.fillMaxWidth()) { showKept() }
            if (!sure) Btn("Forget the whole key on this phone", Kind.Danger, !busy, Modifier.fillMaxWidth()) { sure = true }
            else {
                Warn("After this, the key lives only in pieces. Make sure you have it somewhere else if you want a backup.")
                Btn("Yes, forget the whole key", Kind.Danger, !busy, Modifier.fillMaxWidth()) { store.forgetNsec(); keptKey = false; sure = false; note = "Forgotten. The key now lives only in pieces." }
                Btn("Keep it", enabled = !busy, modifier = Modifier.fillMaxWidth()) { sure = false }
            }
        }
        Card {
            Head("The whole key")
            Dim("Your key lives in pieces. With your fingerprint, this phone can form the whole key, for an app that needs the nsec.")
            Btn("Form the whole key", Kind.Danger, !busy, Modifier.fillMaxWidth()) { showNsec() }
        }
    }

    @Composable private fun JoinCodeScreen(s: Screen.JoinCode) {
        BackHandler { screen = Screen.Home }
        Card {
            Head("${s.name} is added")
            Dim("Scan this with ${s.name} to finish.")
            QrImage(s.text, "Join code for ${s.name}")
            Btn("Copy as text", modifier = Modifier.fillMaxWidth()) { copy(s.text); note = "Copied." }
            Btn("Done", Kind.Main, modifier = Modifier.fillMaxWidth()) { screen = Screen.Home }
        }
    }

    @Composable private fun SiteAskScreen(s: Screen.SiteAsk) {
        BackHandler { screen = Screen.Home }
        val origin = s.params.origin ?: "A site"
        Card {
            Head("Let $origin sign as you?")
            Dim("It gets access of its own. You remove it under Sites here. Removing it stops future signing, not what was already signed.")
            if (!s.viaCamera) Dim("This code was pasted, not scanned, so you will compare five digits with the site next.")
            Btn("Let $origin sign as me", Kind.Main, !busy, Modifier.fillMaxWidth()) { allowSite(s) }
            Btn("Don’t allow", Kind.Danger, !busy, Modifier.fillMaxWidth()) { screen = Screen.Home }
        }
    }

    @Composable private fun SiteDigitsScreen(s: Screen.SiteDigits) {
        BackHandler { digitsAnswer?.offer(false) }
        Card {
            Head("Does ${s.origin} show these digits?")
            androidx.compose.foundation.text.BasicText(s.digits, style = TextStyle(color = palette().text, fontSize = 40.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, letterSpacing = 6.sp))
            Dim("If the site shows different digits, someone else's code got in the way. Say no.")
            Btn("Yes, the same", Kind.Main, modifier = Modifier.fillMaxWidth()) { digitsAnswer?.offer(true) }
            Btn("No, different", Kind.Danger, modifier = Modifier.fillMaxWidth()) { digitsAnswer?.offer(false) }
        }
    }

    @Composable private fun NsecScreen(s: Screen.Nsec) {
        BackHandler { screen = Screen.Home }
        Card {
            Head("The whole key")
            Warn("Anyone who gets this controls the account for good.")
            Mono(Bech32.nsec(s.nsec))
            Btn("Copy", modifier = Modifier.fillMaxWidth()) { copy(Bech32.nsec(s.nsec)); note = "Copied." }
            Btn("Done", Kind.Main, modifier = Modifier.fillMaxWidth()) { screen = Screen.Home }
        }
    }
}
