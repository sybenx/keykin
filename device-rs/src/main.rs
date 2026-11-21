// `keykin`: sign Nostr events from Terminal as your own account (Keykin SPEC 8d, the sealed signer).
//
// This Mac becomes a device of your account, like your phone. Its piece is sealed by the Secure Enclave, and every
// signature asks for Touch ID. No nsec, no bunker link, nothing that signs in a plain file.
//
//   keykin join [--name <name>]   add this Mac: Add on your account page, as Marble on Mac signs in
//   keykin sign ['<event>'|-]     sign an event (JSON; or on stdin) and print it signed
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
use keykin_device::{chip, kinds, signin};
use serde_json::{json, Value};

const HELP: &str = "keykin: sign Nostr events from Terminal as your own account.

  keykin join [--name <name>]   add this Mac to your account (Add on your account page)
  keykin sign ['<event>'|-]     sign an event and print it; Touch ID every time
  keykin status                 who this Mac signs as
  keykin forget                 delete this Mac's sealed piece

An event is JSON with any of kind, content, tags and created_at; the rest is filled in.
Publish it with nak, for example:  keykin sign '{\"kind\":1,\"content\":\"hi\"}' | nak event wss://relay.example";

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
    if let Some(p) = o.get("pubkey") {
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

fn sign(args: &[String]) -> Result<(), String> {
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
    let reason = format!("sign {} as you", kinds::describe(&ev));
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
