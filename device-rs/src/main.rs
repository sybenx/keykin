// `keykin`: sign Nostr events from Terminal as your own account (Keykin SPEC 8d, the sealed signer).
//
// This Mac becomes a device of your account, like your phone. Its piece is sealed by the Secure Enclave, and every
// signature asks for Touch ID. No nsec, no bunker link, nothing that signs in a plain file.
//
//   keykin join [--name <name>]   add this Mac: Add on your account page, as Marble on Mac signs in
//   keykin sign [--for <who>] ['<event>'|-]   sign an event (JSON; or on stdin) and print it signed
//   keykin dm [--for <who>] <npub> ['<text>'|-]   send a private message (NIP-17), one Touch ID
//   keykin encrypt / decrypt <npub> ['<text>'|-]   NIP-44 with someone, as the account
//   keykin status                 who this Mac signs as, and where its file is
//   keykin forget                 delete this Mac's sealed piece
//
// The box decides what is hard to undo. keykin never says Yes for you: what the box asks about is signed in Marble
// or on your phone, and what is never done by accident (level 2) only on your phone.

use std::io::{BufRead, Read};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use keykin_device::core::{self, Failure};
use keykin_device::store::{self, OpenErr};
use keykin_device::{chip, dm, kinds, signin};
use serde_json::{json, Value};

const HELP: &str = "keykin: sign Nostr events from Terminal as your own account.

  keykin join [--name <name>]   add this Mac to your account (Add on your account page)
  keykin sign [--for <who>] ['<event>'|-]
                                sign an event and print it; Touch ID every time, saying
                                what it is and who asked (--for, else the calling script)
  keykin dm [--for <who>] [--relay <url>]... <npub> ['<text>'|-]
                                send a private message as you, with one Touch ID. It goes to
                                the relays they read messages on, and a copy to yours
  keykin encrypt [--for <who>] <npub> ['<text>'|-]
  keykin decrypt [--for <who>] <npub> ['<text>'|-]
                                encrypt for someone, or read what they encrypted for you
                                (NIP-44), and print it; Touch ID every time
  keykin status                 who this Mac signs as
  keykin forget                 delete this Mac's sealed piece

An event is JSON with any of kind, content, tags and created_at; the rest is filled in.
Publish it with nak, for example:  keykin sign '{\"kind\":1,\"content\":\"hi\"}' | nak event wss://relay.example
A private message needs nothing else:  keykin dm npub1… 'hi'";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("join") => join(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("dm") => send_dm(&args[1..]),
        Some("encrypt") => crypt(&args[1..], true),
        Some("decrypt") => crypt(&args[1..], false),
        Some("status") => status(),
        Some("forget") => forget(),
        Some("help" | "--help" | "-h") | None => {
            println!("{HELP}");
            Ok(())
        }
        Some(other) => Err(format!("keykin doesn’t know “{other}”.\n\n{HELP}")),
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime")
}

fn npub(hex_key: &str) -> String {
    let bytes = hex::decode(hex_key).unwrap_or_default();
    bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("npub").unwrap(), &bytes).unwrap_or_else(|_| hex_key.into())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// This Mac's name as it calls itself, and that it is the command line: "Aaron’s MacBook (Terminal)".
fn default_name() -> String {
    let mac = std::process::Command::new("scutil").args(["--get", "ComputerName"]).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty());
    format!("{} (Terminal)", mac.unwrap_or_else(|| "Mac".into()))
}

// --- join -----------------------------------------------------------------------------------------------

fn join(args: &[String]) -> Result<(), String> {
    if let Some(f) = store::load()? {
        return Err(format!("This Mac is already in an account, as “{}” ({}). To join again: keykin forget", f.name, npub(&f.account.npub)));
    }
    chip::available()?;
    let name = flag(args, "--name").unwrap_or_else(default_name);
    // Made before anything is asked: making the chip key, and sealing to it, ask for nothing.
    let chip_key = chip::new_key()?;
    let me = core::new_me(&name);
    let invite = core::invite(&me);
    let asked = signin::start()?;
    let web = std::env::var("MARBLE_WEB").unwrap_or_else(|_| "https://marble.syb.lol".into());
    let url = signin::url(&web, &asked, &invite);

    println!("Adding this Mac to your account as “{name}”.");
    println!();
    println!("1. Your browser opens Marble on the web. It finds your account page.");
    println!("2. Press Add on “Add {name} to your account?”.");
    println!("3. Your browser comes back here and this Mac joins.");
    println!();
    println!("If the browser doesn’t open, go to:\n  {url}");
    println!();
    println!("If your account page shows six digits instead, type them here with its address,");
    println!("for example: 123456 account.example.com. A join code your phone shows can be pasted here too.");
    println!();
    println!("Invite (for your phone’s Add a device): {invite}");
    if std::env::var("KEYKIN_NO_BROWSER").is_err() && !args.iter().any(|a| a == "--no-browser") {
        let _ = std::process::Command::new("open").arg(&url).status();
    }

    let (link_tx, link_rx) = mpsc::channel();
    let (listener, state) = (asked.listener, asked.state.clone());
    std::thread::spawn(move || signin::listen(listener, state, link_tx));
    let (typed_tx, typed_rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { return };
            if typed_tx.send(line).is_err() {
                return;
            }
        }
    });

    let rt = rt();
    let verifier = asked.verifier.as_str();
    let until = Instant::now() + signin::LIFE;
    while Instant::now() < until {
        if let Ok(a) = link_rx.try_recv() {
            let tried = core::read_join(&a.join).map_err(Failure::Refused).and_then(|j| rt.block_on(core::join_with(&me, &j.addr, Some(&j), Some((&a.code, Some(verifier))))));
            match tried {
                Ok(acct) => {
                    store::create(&chip_key, &me, &acct)?;
                    signin::reply(a.tab, 200, &format!("Done. {name} is in your account. You can close this tab."));
                    return joined(&name, &acct.npub);
                }
                Err(f) => {
                    let w = words(&f);
                    signin::reply(a.tab, 200, &format!("This Mac couldn’t join: {w} Go back to your account page and type the code it shows into Terminal."));
                    println!("Couldn’t join: {w}\nType the six digits your account page shows, with its address.");
                }
            }
        }
        let line = match typed_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let tried = if t.starts_with('{') {
            // A join code from a phone that added this invite (no account page, no approval).
            match core::read_join(t) {
                Ok(j) => rt.block_on(core::join(&me, &j)),
                Err(e) => Err(Failure::Refused(e)),
            }
        } else {
            let mut parts = t.split_whitespace();
            let code: String = parts.next().unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
            let page = parts.next().unwrap_or("");
            if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) || page.is_empty() {
                println!("Type the six digits and your account page’s address, for example: 123456 account.example.com");
                continue;
            }
            match signin::page_addr(page) {
                Ok(addr) => rt.block_on(core::join_with(&me, &addr, None, Some((&code, Some(verifier))))),
                Err(e) => {
                    println!("{e}");
                    continue;
                }
            }
        };
        match tried {
            Ok(acct) => {
                store::create(&chip_key, &me, &acct)?;
                return joined(&name, &acct.npub);
            }
            Err(f) => println!("Couldn’t join: {}", words(&f)),
        }
    }
    Err("Ten minutes passed and this Mac didn’t join. Run keykin join again.".into())
}

fn joined(name: &str, npub_hex: &str) -> Result<(), String> {
    println!("Joined. This Mac signs as {} and shows as “{name}” under Devices.", npub(npub_hex));
    println!("Its piece is sealed by the Secure Enclave in {}; every signature asks for Touch ID.", store::path().display());
    Ok(())
}

// --- sign -----------------------------------------------------------------------------------------------

/// The event as asked, filled in: kind 1, no tags and no content unless given, made now, and as this account.
fn event_of(text: &str, npub_hex: &str) -> Result<Value, String> {
    let bad = |w: &str| format!("That isn’t an event keykin can sign: {w}.");
    let v: Value = serde_json::from_str(text.trim()).map_err(|e| bad(&e.to_string()))?;
    let o = v.as_object().ok_or_else(|| bad("give a JSON object"))?;
    // Already signed by another key (`nak event -k 1 -c hi` signs with nak's default key): re-signed here as this
    // account, so `nak event … | keykin sign | nak event <relays>` works. Only an unsigned event naming another
    // pubkey is refused, as that looks like a mistake.
    let resign = o.contains_key("sig");
    if let (false, Some(p)) = (resign, o.get("pubkey")) {
        if p.as_str() != Some(npub_hex) {
            return Err(bad("its pubkey isn’t this account’s"));
        }
    }
    let kind = match o.get("kind") {
        None => 1,
        Some(k) => k.as_u64().filter(|k| *k <= 65535).ok_or_else(|| bad("kind is a number from 0 to 65535"))?,
    };
    let created_at = match o.get("created_at") {
        None => core::now(),
        Some(t) => t.as_u64().ok_or_else(|| bad("created_at is a number of seconds"))?,
    };
    let tags = o.get("tags").cloned().unwrap_or(json!([]));
    let ok_tags = tags.as_array().is_some_and(|ts| ts.iter().all(|t| t.as_array().is_some_and(|t| t.iter().all(Value::is_string))));
    if !ok_tags {
        return Err(bad("tags are lists of strings"));
    }
    let content = o.get("content").cloned().unwrap_or(json!(""));
    if !content.is_string() {
        return Err(bad("content is a string"));
    }
    Ok(json!({ "created_at": created_at, "kind": kind, "tags": tags, "content": content }))
}

/// Who asked for a signature, when the caller didn't say with --for: the script or program that ran keykin.
fn caller() -> Option<String> {
    let ppid = std::os::unix::process::parent_id();
    let out = std::process::Command::new("ps").args(["-o", "args=", "-p", &ppid.to_string()]).output().ok()?;
    caller_name(&String::from_utf8_lossy(&out.stdout))
}
/// The name to show for a calling command line: "/bin/bash ./zapstore.sh --x" is "zapstore.sh", not the shell.
fn caller_name(cmd: &str) -> Option<String> {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let pick = words.iter().skip(1).find(|w| !w.starts_with('-') && w.contains('.') && !w.contains('=')).or(words.first())?;
    let name = pick.rsplit('/').next()?.trim_start_matches('-').to_string();
    // Typed in Terminal: the shell itself says nothing about who asked.
    (!name.is_empty() && !["zsh", "bash", "sh", "fish", "dash", "login"].contains(&name.as_str())).then_some(name)
}

#[cfg(test)]
mod caller_tests {
    #[test]
    fn the_script_not_the_shell() {
        assert_eq!(super::caller_name("/bin/bash ./zapstore.sh --release").as_deref(), Some("zapstore.sh"));
        assert_eq!(super::caller_name("sh /Users/a/src/wisp-release/zapstore.sh").as_deref(), Some("zapstore.sh"));
        assert_eq!(super::caller_name("-zsh"), None);
        assert_eq!(super::caller_name("/bin/zsh -il"), None);
        assert_eq!(super::caller_name("node /x/publish.mjs a=b").as_deref(), Some("publish.mjs"));
        assert_eq!(super::caller_name(""), None);
    }
}

/// --for "<who>": who is asking, said in the Touch ID prompt ("…, for Pinket's release"). Otherwise the caller's name.
/// Returns the other arguments, and who.
fn take_for(args: &[String], example: &str) -> Result<(Vec<String>, Option<String>), String> {
    let mut args = args.to_vec();
    let mut who = None;
    if let Some(i) = args.iter().position(|a| a == "--for") {
        if i + 1 >= args.len() {
            return Err(format!("--for needs who is asking, for example: {example}"));
        }
        who = Some(args.remove(i + 1).chars().filter(|c| !c.is_control()).take(60).collect::<String>());
        args.remove(i);
    }
    Ok((args, who.filter(|w| !w.trim().is_empty()).or_else(caller)))
}

fn sign(args: &[String]) -> Result<(), String> {
    let (args, who) = take_for(args, "keykin sign --for \"Pinket release\" '<event>'")?;
    let args = &args[..];
    let mut f = store::load()?.ok_or("This Mac isn’t in an account yet. Run: keykin join")?;
    use std::io::IsTerminal;
    let at_keyboard = std::io::stdin().is_terminal();
    let text = match args.first().map(String::as_str) {
        // Typed alone at the keyboard: say what it needs, rather than wait silently for an event on stdin.
        None if at_keyboard => {
            return Err("Give the event to sign, for example:\n  keykin sign '{\"kind\":1,\"content\":\"hello\"}'\nor pipe it in: echo '{\"kind\":1,\"content\":\"hello\"}' | keykin sign".into());
        }
        None | Some("-") => {
            if at_keyboard {
                eprintln!("Paste the event, then press Ctrl-D.");
            }
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
            s
        }
        Some(t) => t.to_string(),
    };
    let ev = event_of(&text, &f.account.npub)?;
    // macOS says: “keykin is trying to <this>”.
    let reason = match &who {
        Some(w) => format!("sign {} as you, for {w}", kinds::describe(&ev)),
        None => format!("sign {} as you", kinds::describe(&ev)),
    };
    let (me, mut a) = store::open(&f, &reason).map_err(|e| match e {
        OpenErr::No => "Not signed: Touch ID wasn’t confirmed.".to_string(),
        OpenErr::Failed(w) => format!("Not signed: {w}"),
    })?;
    let epoch = a.epoch;
    let r = rt().block_on(core::sign_event(&me, &mut a, &ev, false));
    // The box moved this Mac to a new epoch (the keys were cycled while it was away): keep that, sealed afresh.
    if a.epoch != epoch {
        if let Err(e) = store::resave(&mut f, &me, &a) {
            eprintln!("keykin couldn’t save the new keys: {e}");
        }
    }
    match r {
        Ok(signed) => {
            println!("{signed}");
            Ok(())
        }
        Err(fail) => Err(format!("Not signed: {}", words(&fail))),
    }
}

// --- dm, encrypt, decrypt -----------------------------------------------------------------------------

/// Someone's key as hex, from an npub or 64 hex digits.
fn key_of(s: &str) -> Result<String, String> {
    let s = s.trim().trim_start_matches("nostr:");
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(s.to_lowercase());
    }
    match bech32::decode(s) {
        Ok((hrp, data)) if hrp.as_str() == "npub" && data.len() == 32 => Ok(hex::encode(data)),
        _ => Err(format!("“{s}” isn’t someone’s npub (or their key as 64 hex digits).")),
    }
}

/// "npub1syjmjy0d…9wf6wl": enough to tell one key from another.
fn short_npub(hex_key: &str) -> String {
    let n = npub(hex_key);
    format!("{}…{}", &n[..13.min(n.len())], &n[n.len().saturating_sub(6)..])
}

/// The first words of a message, on one line, for the Touch ID prompt.
fn first_words(text: &str) -> String {
    let t: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let short: String = t.chars().take(50).collect();
    if t.chars().count() > 50 { format!("{short}…") } else { short }
}

/// The text to send or read: given, or on stdin ("-", or nothing with stdin not at the keyboard).
fn text_arg(given: Option<&String>, example: &str) -> Result<String, String> {
    use std::io::IsTerminal;
    let at_keyboard = std::io::stdin().is_terminal();
    let text = match given.map(String::as_str) {
        None if at_keyboard => return Err(format!("Give the text, for example:\n  {example}\nor pipe it in.")),
        None | Some("-") => {
            if at_keyboard {
                eprintln!("Type or paste it, then press Ctrl-D.");
            }
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
            // What `echo` and a file end with isn't part of the message.
            s.trim_end_matches(['\n', '\r']).to_string()
        }
        Some(t) => t.to_string(),
    };
    if text.trim().is_empty() {
        return Err("There’s nothing to send: the text is empty.".into());
    }
    Ok(text)
}

fn not_done(e: OpenErr) -> String {
    match e {
        OpenErr::No => "Not sent: Touch ID wasn’t confirmed.".to_string(),
        OpenErr::Failed(w) => format!("Not sent: {w}"),
    }
}

/// The box moved this Mac to a new epoch (the keys were cycled while it was away): keep that, sealed afresh.
fn keep_epoch(f: &mut store::File, me: &core::Me, a: &core::Account, before: u64) {
    if a.epoch != before {
        if let Err(e) = store::resave(f, me, a) {
            eprintln!("keykin couldn’t save the new keys: {e}");
        }
    }
}

/// The longest message keykin sends: what still fits, wrapped twice, in what relays take (NIP-44 stops at 64 KB).
const DM_MAX: usize = 32_000;

fn send_dm(args: &[String]) -> Result<(), String> {
    let example = "keykin dm npub1… 'hello'";
    let (mut args, who) = take_for(args, "keykin dm --for \"weekly report\" npub1… 'hello'")?;
    // --relay <url>, as many as wanted: send there instead of where the lists say (both copies).
    let mut given = vec![];
    while let Some(i) = args.iter().position(|a| a == "--relay") {
        let u = args.get(i + 1).cloned().ok_or("--relay needs a relay’s address, for example: --relay wss://relay.example")?;
        given.push(dm::relay_url(&u).ok_or(format!("“{u}” isn’t a relay’s address (wss://…)."))?);
        args.drain(i..i + 2);
    }
    let to = key_of(args.first().ok_or(format!("Say who it is for, for example:\n  {example}"))?)?;
    if args.len() > 2 {
        return Err(format!("Put the message in quotes, for example:\n  {example}"));
    }
    let text = text_arg(args.get(1), example)?;
    if text.len() > DM_MAX {
        return Err(format!("That message is {} bytes; a private message from keykin is at most {DM_MAX}.", text.len()));
    }
    let mut f = store::load()?.ok_or("This Mac isn’t in an account yet. Run: keykin join")?;
    let me_hex = f.account.npub.clone();
    let to_me = to == me_hex;
    let rt = rt();

    // Who they are and where they read messages, before anything is asked: no Touch ID for a message with nowhere to go.
    let found = rt.block_on(dm::fetch(&dm::lookup_relays(), json!({ "authors": [to, me_hex], "kinds": [0, 10002, 10050] })));
    let (to_relays, my_relays) = if given.is_empty() { (dm::dm_relays(&found, &to), dm::dm_relays(&found, &me_hex)) } else { (given.clone(), given.clone()) };
    let label = if to_me {
        "yourself".to_string()
    } else {
        match dm::display_name(&found, &to) {
            Some(n) => format!("{n} ({})", short_npub(&to)),
            None => short_npub(&to),
        }
    };
    if to_relays.is_empty() {
        return Err(format!("Not sent: {label} lists no relays for private messages, so there is nowhere they would read it. To send it anyway, name one with --relay wss://…"));
    }

    // macOS says: “keykin is trying to <this>”.
    let what = format!("send a private message to {label}: “{}”", first_words(&text));
    let reason = match &who {
        Some(w) => format!("{what}, for {w}"),
        None => what,
    };
    let (me, mut a) = store::open(&f, &reason).map_err(not_done)?;
    let epoch = a.epoch;
    let readers: Vec<&str> = if to_me { vec![&to] } else { vec![&to, &me_hex] };
    let made: Result<Vec<serde_json::Value>, String> = rt.block_on(async {
        let now = core::now();
        let rumor = dm::rumor(&me_hex, &to, &text, now)?;
        let mut wraps = vec![];
        for reader in &readers {
            let ck = core::conversation_key(&me, &mut a, reader).await.map_err(|f| words(&f))?;
            let seal = core::sign_event(&me, &mut a, &dm::seal_unsigned(&ck, &rumor, now)?, false).await.map_err(|f| words(&f))?;
            wraps.push(dm::wrap(&seal, reader, now)?);
        }
        Ok(wraps)
    });
    keep_epoch(&mut f, &me, &a, epoch);
    let wraps = made.map_err(|e| format!("Not sent: {e}"))?;

    let (theirs, mine) = rt.block_on(async {
        let mine = async {
            match wraps.get(1) {
                Some(w) if !my_relays.is_empty() => dm::publish(&my_relays, w).await,
                _ => vec![],
            }
        };
        futures_util::future::join(dm::publish(&to_relays, &wraps[0]), mine).await
    });
    let report = |who: &str, rs: &[(String, Result<(), String>)]| -> bool {
        let ok: Vec<&str> = rs.iter().filter(|(_, r)| r.is_ok()).map(|(u, _)| u.as_str()).collect();
        println!("{who}: {}", if ok.is_empty() { "on no relay".to_string() } else { ok.join(", ") });
        for (u, r) in rs {
            if let Err(e) = r {
                println!("  {u} didn’t take it: {e}");
            }
        }
        !ok.is_empty()
    };
    let landed = report(&format!("Sent to {label}"), &theirs);
    if !to_me {
        if my_relays.is_empty() {
            println!("Your copy: not kept, as your account lists no relays for private messages.");
        } else {
            report("Your copy", &mine);
        }
    }
    if !landed {
        return Err("Not sent: no relay took the message.".into());
    }
    Ok(())
}

/// `keykin encrypt <npub> <text>` and `keykin decrypt <npub> <payload>`: NIP-44 with that key, as the account.
fn crypt(args: &[String], encrypting: bool) -> Result<(), String> {
    let cmd = if encrypting { "encrypt" } else { "decrypt" };
    let example = format!("keykin {cmd} npub1… '{}'", if encrypting { "hello" } else { "Ag…" });
    let (args, who) = take_for(args, &format!("keykin {cmd} --for \"my script\" npub1… '…'"))?;
    let peer = key_of(args.first().ok_or(format!("Say whose key, for example:\n  {example}"))?)?;
    let text = text_arg(args.get(1), &example)?;
    let mut f = store::load()?.ok_or("This Mac isn’t in an account yet. Run: keykin join")?;
    let what = if encrypting {
        format!("encrypt a private message to {}: “{}”", short_npub(&peer), first_words(&text))
    } else {
        format!("read a private message from {}", short_npub(&peer))
    };
    let reason = match &who {
        Some(w) => format!("{what}, for {w}"),
        None => what,
    };
    let (me, mut a) = store::open(&f, &reason).map_err(|e| not_done(e).replace("Not sent", if encrypting { "Not encrypted" } else { "Not read" }))?;
    let epoch = a.epoch;
    let ck = rt().block_on(core::conversation_key(&me, &mut a, &peer));
    keep_epoch(&mut f, &me, &a, epoch);
    let ck = ck.map_err(|f| words(&f))?;
    println!("{}", if encrypting { dm::encrypt(&ck, &text)? } else { dm::decrypt(&ck, &text)? });
    Ok(())
}

/// A failure in words for Terminal. keykin never says Yes for you (no `tapped`, no fingerprint).
fn words(f: &Failure) -> String {
    if f.code() == "needs_tap" {
        let why = f.why().map(|w| w.trim_end_matches(['.', ' ']).to_string()).unwrap_or_else(|| "Your box asks for your Yes before signing this".into());
        return format!("{why}. keykin doesn’t say Yes for you: sign it in Marble or on your phone.");
    }
    if f.removed() {
        return format!("{} To clear this Mac’s file: keykin forget", f.words());
    }
    f.words()
}

// --- status, forget -----------------------------------------------------------------------------------

fn status() -> Result<(), String> {
    let Some(f) = store::load()? else {
        println!("This Mac isn’t in an account. Add it with: keykin join");
        return Ok(());
    };
    println!("{}", npub(&f.account.npub));
    println!("npub (hex): {}", f.account.npub);
    println!("This Mac: “{}”, piece {}, box at {}", f.name, f.account.i, f.account.addr);
    println!("Sealed by the Secure Enclave in {}", store::path().display());
    Ok(())
}

fn forget() -> Result<(), String> {
    let f = store::load().ok().flatten();
    if !store::forget()? {
        println!("There was nothing to forget.");
        return Ok(());
    }
    match f {
        Some(f) => println!("Forgot this Mac’s piece. If “{}” is still under Devices, block it on your phone or your account page.", f.name),
        None => println!("Forgot this Mac’s file."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_filled_in_and_checked() {
        let n = "ab".repeat(32);
        let e = event_of("{}", &n).unwrap();
        assert_eq!((e["kind"].as_u64(), e["content"].as_str(), e["tags"].clone()), (Some(1), Some(""), json!([])));
        assert!(e["created_at"].as_u64().unwrap() > 1_700_000_000);
        let e = event_of(r#"{"kind":31990,"tags":[["d","x"],["k","1"]],"content":"{}","created_at":5}"#, &n).unwrap();
        assert_eq!(e["kind"], json!(31990));
        assert_eq!(e["created_at"], json!(5));
        assert!(event_of(&format!(r#"{{"pubkey":"{}"}}"#, "cd".repeat(32)), &n).unwrap_err().contains("pubkey"));
        assert!(event_of(r#"{"tags":[["p",1]]}"#, &n).is_err());
        assert!(event_of(r#"{"kind":-1}"#, &n).is_err());
        assert!(event_of("[1]", &n).is_err());
        // nak's output, signed by its own key: taken, and its id, pubkey and sig left behind.
        let e = event_of(&format!(r#"{{"kind":1,"id":"{0}","pubkey":"{1}","created_at":7,"tags":[],"content":"hi","sig":"{0}{0}"}}"#, "ee".repeat(32), "cd".repeat(32)), &n).unwrap();
        assert_eq!(e, json!({ "created_at": 7, "kind": 1, "tags": [], "content": "hi" }));
    }

    #[test]
    fn keys_and_first_words() {
        let hex = "8125b911ed0e94dbe3008a0be48cfe5cd0c0b05923cfff917ae7e87da84008830";
        let hex = &hex[..64];
        let n = npub(hex);
        assert_eq!(key_of(&n).unwrap(), hex);
        assert_eq!(key_of(&format!("nostr:{n}")).unwrap(), hex);
        assert_eq!(key_of(&hex.to_uppercase()).unwrap(), hex);
        assert!(key_of("npub1nope").is_err());
        assert!(short_npub(hex).starts_with("npub1") && short_npub(hex).contains('…'));
        assert_eq!(first_words("hi\n  there"), "hi there");
        assert!(first_words(&"a ".repeat(60)).ends_with('…'));
    }

    #[test]
    fn refusals_say_where_it_is_done() {
        let tap = Failure::Said { code: "needs_tap".into(), why: "Remove 10 of your 30 follows".into() };
        assert_eq!(words(&tap), "Remove 10 of your 30 follows. keykin doesn’t say Yes for you: sign it in Marble or on your phone.");
        let l2 = Failure::Said { code: "needs_fingerprint".into(), why: "Empty your follow list".into() };
        assert_eq!(words(&l2), "Empty your follow list. Do this from your phone.");
        assert!(words(&Failure::Refused("blocked".into())).contains("keykin forget"));
    }
}
