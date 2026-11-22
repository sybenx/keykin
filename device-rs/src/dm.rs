// Private messages from this device (Keykin SPEC 8d, `keykin dm`): NIP-44 v2 encryption, NIP-17's message
// wrapped twice (NIP-59), and just enough of a relay client to find where someone reads their messages and to
// leave the message there.
//
// The account's key is never whole here either. Its side of a shared secret comes from `core::conversation_key`
// (this piece and the box's part, §8a), and the seal is signed by `core::sign_event`, as `keykin sign` signs. Only
// the outer wrap is signed here, by a key made for that one wrap and dropped after.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

use crate::core::{self, R};

// --- NIP-44 v2 --------------------------------------------------------------------------------------

/// The NIP-44 conversation key between a secret key held here (hex) and `peer` (x-only hex).
pub fn conversation_key_local(sk: &str, peer: &str) -> R<[u8; 32]> {
    let shared = core::lift_x(peer)? * core::scalar(sk, "key")?;
    Ok(core::nip44_key(&core::x_of(&shared)?))
}

fn message_keys(ck: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(ck).expect("a 32-byte key");
    let mut okm = [0u8; 76];
    hk.expand(nonce, &mut okm).expect("76 bytes");
    (okm[..32].try_into().unwrap(), okm[32..44].try_into().unwrap(), okm[44..].try_into().unwrap())
}

fn padded_len(n: usize) -> usize {
    if n <= 32 {
        return 32;
    }
    let next = 1usize << (usize::BITS - (n - 1).leading_zeros());
    let chunk = if next <= 256 { 32 } else { next / 8 };
    chunk * ((n - 1) / chunk + 1)
}

fn mac_of(key: &[u8; 32], nonce: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    m.update(nonce);
    m.update(ct);
    m.finalize().into_bytes().into()
}

/// NIP-44 v2: `text` encrypted with the conversation key `ck`, as base64.
pub fn encrypt(ck: &[u8; 32], text: &str) -> R<String> {
    encrypt_with(ck, text, &core::random32())
}

pub fn encrypt_with(ck: &[u8; 32], text: &str, nonce: &[u8; 32]) -> R<String> {
    let n = text.len();
    if n == 0 || n > 65535 {
        return Err("a message is 1 to 65535 bytes".into());
    }
    let (key, iv, hkey) = message_keys(ck, nonce);
    let mut buf = vec![0u8; 2 + padded_len(n)];
    buf[..2].copy_from_slice(&(n as u16).to_be_bytes());
    buf[2..2 + n].copy_from_slice(text.as_bytes());
    chacha20::ChaCha20::new((&key).into(), (&iv).into()).apply_keystream(&mut buf);
    let mac = mac_of(&hkey, nonce, &buf);
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode([&[2u8][..], nonce, &buf, &mac].concat()))
}

/// NIP-44 v2, back to the text. A wrong key, or anything changed on the way, fails the MAC check.
pub fn decrypt(ck: &[u8; 32], payload: &str) -> R<String> {
    use base64::Engine;
    let bad = || "That isn’t a message this account can read.".to_string();
    let raw = base64::engine::general_purpose::STANDARD.decode(payload.trim()).map_err(|_| bad())?;
    if raw.len() < 99 || raw[0] != 2 {
        return Err(bad());
    }
    let nonce: [u8; 32] = raw[1..33].try_into().unwrap();
    let (ct, mac) = raw[33..].split_at(raw.len() - 33 - 32);
    let (key, iv, hkey) = message_keys(ck, &nonce);
    use subtle_eq::eq;
    if !eq(&mac_of(&hkey, &nonce, ct), mac) {
        return Err(bad());
    }
    let mut buf = ct.to_vec();
    chacha20::ChaCha20::new((&key).into(), (&iv).into()).apply_keystream(&mut buf);
    let n = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if n == 0 || buf.len() != 2 + padded_len(n) {
        return Err(bad());
    }
    String::from_utf8(buf[2..2 + n].to_vec()).map_err(|_| bad())
}

mod subtle_eq {
    /// Equal, in time that doesn't depend on where they differ.
    pub fn eq(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
    }
}

// --- NIP-17 and NIP-59 -------------------------------------------------------------------------------

/// A time up to two days back, so a seal or a wrap doesn't say when it was made (NIP-59).
fn some_time_before(now: u64) -> u64 {
    let r = u64::from_le_bytes(core::random32()[..8].try_into().unwrap());
    now - r % (2 * 24 * 3600)
}

/// The message itself (kind 14), from `from` to `to`, never signed: it has an id, and no signature.
pub fn rumor(from: &str, to: &str, text: &str, now: u64) -> R<Value> {
    let mut r = json!({ "pubkey": from, "created_at": now, "kind": 14, "tags": [["p", to]], "content": text });
    r["id"] = json!(core::event_id(&r)?);
    Ok(r)
}

/// The seal (kind 13) as it is signed: the rumor, encrypted with the account's conversation key with the reader.
pub fn seal_unsigned(ck: &[u8; 32], rumor: &Value, now: u64) -> R<Value> {
    Ok(json!({ "created_at": some_time_before(now), "kind": 13, "tags": [], "content": encrypt(ck, &rumor.to_string())? }))
}

/// Signs `ev` with a secret key held here (hex): fills in pubkey, id and sig.
pub fn sign_local(sk: &str, ev: &Value) -> R<Value> {
    let mut out = json!({ "pubkey": core::x_only_of(sk)?, "created_at": ev["created_at"], "kind": ev["kind"], "tags": ev["tags"], "content": ev["content"] });
    let id = core::event_id(&out)?;
    let sig = core::schnorr_sign(sk, &hex::decode(&id).unwrap().try_into().unwrap())?;
    out["id"] = json!(id);
    out["sig"] = json!(sig);
    Ok(out)
}

/// A gift wrap (kind 1059) ready to leave: the key made for this wrap alone, and the wrap before it is signed. The
/// key also logs in to a relay that asks (NIP-42), and the wrap is mined for one that wants work (NIP-13): neither
/// needs the account, so neither asks for anything.
pub struct Wrap {
    pub sk: String,
    pub unsigned: Value,
}

impl Wrap {
    /// The wrap signed, with no work done.
    pub fn signed(&self) -> R<Value> {
        sign_local(&self.sk, &self.unsigned)
    }

    /// The wrap with an id starting with at least `bits` zero bits (NIP-13), signed. A nonce tag is the only change.
    pub fn mined(&self, bits: u32) -> R<Value> {
        if bits == 0 {
            return self.signed();
        }
        if bits > MAX_POW {
            return Err(format!("asks for proof of work of {bits}, more than keykin does ({MAX_POW})"));
        }
        // The id is sha256 of the event as JSON; only the nonce changes, so the JSON is cut around it once.
        const MARK: &str = "kk-nonce-here";
        let mut ev = self.unsigned.clone();
        ev["pubkey"] = json!(core::x_only_of(&self.sk)?);
        let mut tags = ev["tags"].as_array().cloned().unwrap_or_default();
        tags.push(json!(["nonce", MARK, bits.to_string()]));
        let arr = json!([0, ev["pubkey"], ev["created_at"], ev["kind"], tags, ev["content"]]);
        let text = serde_json::to_string(&arr).map_err(|e| e.to_string())?;
        let (before, after) = text.split_once(MARK).ok_or("no nonce")?;
        use sha2::Digest;
        let mut head = Sha256::new();
        head.update(before.as_bytes());
        for n in 0u64.. {
            let mut h = head.clone();
            h.update(n.to_string().as_bytes());
            h.update(after.as_bytes());
            if zero_bits(&h.finalize()) >= bits {
                let last = tags.len() - 1;
                tags[last][1] = json!(n.to_string());
                ev["tags"] = json!(tags);
                return sign_local(&self.sk, &ev);
            }
        }
        unreachable!()
    }
}

/// The most work keykin does for a relay: 24 bits is about 16 million tries, some seconds.
pub const MAX_POW: u32 = 24;

/// How many zero bits an id starts with (NIP-13).
pub fn zero_bits(id: &[u8]) -> u32 {
    let mut n = 0;
    for b in id {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// The gift wrap for `to`: the signed seal, encrypted with a key made for this wrap alone.
pub fn wrap(seal: &Value, to: &str, now: u64) -> R<Wrap> {
    let sk = hex::encode(core::random32());
    let ck = conversation_key_local(&sk, to)?;
    let unsigned = json!({ "created_at": some_time_before(now), "kind": 1059, "tags": [["p", to]], "content": encrypt(&ck, &seal.to_string())? });
    Ok(Wrap { sk, unsigned })
}

/// Whether an event from a relay is what it says: its id is its contents, and its author signed it.
pub fn verified(ev: &Value) -> bool {
    let Ok(id) = core::event_id(ev) else { return false };
    let (Some(pk), Some(sig)) = (ev["pubkey"].as_str(), ev["sig"].as_str()) else { return false };
    ev["id"].as_str() == Some(&id) && core::schnorr_verify(pk, &hex::decode(&id).unwrap().try_into().unwrap(), sig)
}

// --- Who someone is, and where they read private messages ---------------------------------------------

/// The newest of `kind` by `author` among `events`.
pub fn newest<'a>(events: &'a [Value], author: &str, kind: u64) -> Option<&'a Value> {
    events.iter().filter(|e| e["pubkey"].as_str() == Some(author) && e["kind"].as_u64() == Some(kind)).max_by_key(|e| e["created_at"].as_u64().unwrap_or(0))
}

pub fn relay_url(u: &str) -> Option<String> {
    let u = u.trim().trim_end_matches('/');
    let ok = (u.starts_with("wss://") || u.starts_with("ws://")) && url::Url::parse(u).is_ok() && !u.contains(char::is_whitespace);
    ok.then(|| u.to_string())
}

/// Where `author` reads private messages: their list for that (kind 10050), else the relays they read from (kind 10002).
pub fn dm_relays(events: &[Value], author: &str) -> Vec<String> {
    let tags = |e: &Value| e["tags"].as_array().cloned().unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let add = |out: &mut Vec<String>, u: Option<String>| {
        if let Some(u) = u.filter(|u| !out.contains(u)) {
            out.push(u);
        }
    };
    if let Some(e) = newest(events, author, 10050) {
        for t in tags(e).iter().filter(|t| t[0] == "relay") {
            add(&mut out, t[1].as_str().and_then(relay_url));
        }
    }
    if out.is_empty() {
        if let Some(e) = newest(events, author, 10002) {
            for t in tags(e).iter().filter(|t| t[0] == "r" && (t.get(2).is_none() || t[2] == "read")) {
                add(&mut out, t[1].as_str().and_then(relay_url));
            }
        }
    }
    out
}

/// The name someone goes by (kind 0), cleaned for a prompt: no control characters, at most 40 characters.
pub fn display_name(events: &[Value], author: &str) -> Option<String> {
    let p: Value = serde_json::from_str(newest(events, author, 0)?["content"].as_str()?).ok()?;
    let n = ["display_name", "displayName", "name"].iter().filter_map(|k| p[*k].as_str()).map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>()).map(|s| s.trim().to_string()).find(|s| !s.is_empty())?;
    Some(n.chars().take(40).collect())
}

// --- Relays ----------------------------------------------------------------------------------------

/// Where to look people up when nothing else is said (KEYKIN_LOOKUP_RELAYS: others, comma separated).
pub fn lookup_relays() -> Vec<String> {
    match std::env::var("KEYKIN_LOOKUP_RELAYS") {
        Ok(v) if !v.trim().is_empty() => v.split(',').filter_map(relay_url).collect(),
        _ => ["wss://purplepag.es", "wss://user.kindpag.es", "wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"].map(String::from).to_vec(),
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(relay: &str) -> R<Ws> {
    match tokio::time::timeout(Duration::from_secs(6), tokio_tungstenite::connect_async(relay)).await {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(e)) => Err(format!("couldn’t connect ({e})")),
        Err(_) => Err("didn’t answer".into()),
    }
}

/// The events one relay has for `filters`, up to its end of stored events, within a few seconds. Each filter is its
/// own subscription: some relays answer a filter naming several kinds with only some of them (purplepag.es did).
async fn fetch_one(relay: &str, filters: &[Value]) -> Vec<Value> {
    let Ok(mut ws) = connect(relay).await else { return vec![] };
    let mut got = vec![];
    let mut open: Vec<String> = vec![];
    for (i, f) in filters.iter().enumerate() {
        let id = format!("kk{i}");
        if ws.send(Message::text(json!(["REQ", id, f]).to_string())).await.is_err() {
            break;
        }
        open.push(id);
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !open.is_empty() {
        let Ok(Some(Ok(m))) = tokio::time::timeout_at(until, ws.next()).await else { break };
        let Ok(v) = serde_json::from_str::<Value>(m.to_text().unwrap_or("")) else { continue };
        let sub = v[1].as_str().unwrap_or("");
        match v[0].as_str() {
            Some("EVENT") if open.iter().any(|o| o == sub) && verified(&v[2]) => got.push(v[2].clone()),
            Some("EOSE" | "CLOSED") => {
                open.retain(|o| o != sub);
                let _ = ws.send(Message::text(json!(["CLOSE", sub]).to_string())).await;
            }
            _ => {}
        }
    }
    let _ = ws.close(None).await;
    got
}

/// What all of `relays` have for `filters`, asked at once.
pub async fn fetch(relays: &[String], filters: &[Value]) -> Vec<Value> {
    futures_util::future::join_all(relays.iter().map(|r| fetch_one(r, filters))).await.into_iter().flatten().collect()
}

/// Everything known about `people`'s names and relays (kinds 0, 10002 and 10050): from the lookup relays first, one
/// subscription per person and kind, then from the relays each says they write to, where their own lists live too.
/// Every version found is kept; `newest` picks.
pub async fn lookup(people: &[&str]) -> Vec<Value> {
    let filters = |kinds: &[u64]| -> Vec<Value> { people.iter().flat_map(|p| kinds.iter().map(move |k| json!({ "authors": [p], "kinds": [k], "limit": 1 }))).collect() };
    let mut found = fetch(&lookup_relays(), &filters(&[0, 10002, 10050])).await;
    let mut more: Vec<String> = vec![];
    for p in people {
        for r in write_relays(&found, p).into_iter().take(6) {
            if !more.contains(&r) && !lookup_relays().contains(&r) {
                more.push(r);
            }
        }
    }
    found.extend(fetch(&more, &filters(&[0, 10050])).await);
    found
}

/// The relays `author` writes to (kind 10002: marked write, or not marked).
pub fn write_relays(events: &[Value], author: &str) -> Vec<String> {
    let mut out = vec![];
    if let Some(e) = newest(events, author, 10002) {
        for t in e["tags"].as_array().into_iter().flatten().filter(|t| t[0] == "r" && (t.get(2).is_none() || t[2] == "write")) {
            if let Some(u) = t[1].as_str().and_then(relay_url).filter(|u| !out.contains(u)) {
                out.push(u);
            }
        }
    }
    out
}

/// The proof of work a relay says it wants, from its NIP-11 document (`limitation.min_pow_difficulty`).
pub fn pow_of_info(info: &Value) -> u32 {
    info["limitation"]["min_pow_difficulty"].as_u64().unwrap_or(0).min(255) as u32
}

/// The proof of work a refusal asks for: "pow: difficulty 0 is less than the 16 this relay requires" is 16.
pub fn pow_of_refusal(msg: &str) -> Option<u32> {
    if !msg.starts_with("pow:") {
        return None;
    }
    msg.split(|c: char| !c.is_ascii_digit()).filter_map(|n| n.parse::<u32>().ok()).max().filter(|n| *n > 0)
}

async fn relay_info(relay: &str) -> Value {
    let http = relay.replacen("wss://", "https://", 1).replacen("ws://", "http://", 1);
    let get = async {
        let c = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().ok()?;
        c.get(&http).header("Accept", "application/nostr+json").send().await.ok()?.json::<Value>().await.ok()
    };
    get.await.unwrap_or(Value::Null)
}

/// The login a relay asks for (NIP-42, kind 22242), signed by the wrap's own key: never the account's.
pub fn login(sk: &str, relay: &str, challenge: &str) -> R<Value> {
    sign_local(sk, &json!({ "created_at": core::now(), "kind": 22242, "tags": [["relay", relay], ["challenge", challenge]], "content": "" }))
}

/// Leaves the wrap on one relay. Ok when it says it took it; its words when it refused. A relay that asks for proof
/// of work (in its NIP-11 document, or in its refusal) gets the wrap mined to that; one that asks for a login gets
/// one by the wrap's key, and the wrap again.
pub async fn publish_one(relay: &str, w: &Wrap) -> R<()> {
    let (info, ws) = futures_util::future::join(relay_info(relay), connect(relay)).await;
    let mut ws = ws?;
    let mut ev = w.mined(pow_of_info(&info))?;
    let send = |v: Value| Message::text(v.to_string());
    ws.send(send(json!(["EVENT", ev]))).await.map_err(|e| e.to_string())?;
    let mut challenge: Option<String> = None;
    let (mut wants_login, mut login_id, mut logged_in, mut mined) = (false, None::<Value>, false, false);
    let mut until = tokio::time::Instant::now() + Duration::from_secs(15);
    let r = loop {
        let m = match tokio::time::timeout_at(until, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(_) => break Err("closed the connection".into()),
            Err(_) => break Err("didn’t answer".into()),
        };
        let Ok(v) = serde_json::from_str::<Value>(m.to_text().unwrap_or("")) else { continue };
        let said = v[3].as_str().filter(|s| !s.is_empty()).unwrap_or("refused").to_string();
        match v[0].as_str() {
            Some("AUTH") => {
                challenge = v[1].as_str().map(str::to_string);
                if wants_login && login_id.is_none() {
                    let l = login(&w.sk, relay, challenge.as_deref().unwrap_or(""))?;
                    login_id = Some(l["id"].clone());
                    ws.send(send(json!(["AUTH", l]))).await.map_err(|e| e.to_string())?;
                }
            }
            Some("OK") if login_id.as_ref() == Some(&v[1]) => {
                if v[2] != true {
                    break Err(format!("refused the login: {said}"));
                }
                logged_in = true;
                login_id = Some(Value::Null);
                ws.send(send(json!(["EVENT", ev]))).await.map_err(|e| e.to_string())?;
            }
            Some("OK") if v[1] == ev["id"] => {
                if v[2] == true {
                    break Ok(());
                }
                if said.starts_with("auth-required") && !logged_in && !wants_login {
                    // Log in now if it has said its challenge; else when it does.
                    wants_login = true;
                    if let Some(c) = &challenge {
                        let l = login(&w.sk, relay, c)?;
                        login_id = Some(l["id"].clone());
                        ws.send(send(json!(["AUTH", l]))).await.map_err(|e| e.to_string())?;
                    }
                    continue;
                }
                match pow_of_refusal(&said) {
                    Some(bits) if !mined => {
                        mined = true;
                        ev = w.mined(bits).map_err(|e| format!("{said} (keykin {e})"))?;
                        until = tokio::time::Instant::now() + Duration::from_secs(15);
                        ws.send(send(json!(["EVENT", ev]))).await.map_err(|e| e.to_string())?;
                    }
                    _ => break Err(said),
                }
            }
            _ => {}
        }
    };
    let _ = ws.close(None).await;
    r
}

/// Leaves the wrap on each of `relays`, all at once: (relay, how it went).
pub async fn publish(relays: &[String], w: &Wrap) -> Vec<(String, R<()>)> {
    let rs = futures_util::future::join_all(relays.iter().map(|r| publish_one(r, w))).await;
    relays.iter().cloned().zip(rs).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const TWO: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn nip44_matches_the_spec_and_nostr_tools() {
        let ck = conversation_key_local(ONE, &core::x_only_of(TWO).unwrap()).unwrap();
        assert_eq!(hex::encode(ck), "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
        let nonce: [u8; 32] = hex::decode(ONE).unwrap().try_into().unwrap();
        // NIP-44's first vector.
        assert_eq!(encrypt_with(&ck, "a", &nonce).unwrap(), "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb");
        // nostr-tools' v2.encrypt for a longer one.
        let long = "🍕🫃 hello there, a slightly longer private message that goes past thirty-two bytes";
        let p = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABebuXetkfI2DzSbJmCWcvRtZwalWFg8lEfgAHe+mXxbc2cJoHGQ2JtL91EzNGydy0TZRCxNLi++6I8kcXENz1Lmc/t1U1ka9TL/Unakk/8rd+fIN6O3qcgZavbrA183o2w/iGdSpMSdtLyzbFu8CsZf70uUlN/bNWL2XQW8HdTz/70w==";
        assert_eq!(encrypt_with(&ck, long, &nonce).unwrap(), p);
        assert_eq!(decrypt(&ck, p).unwrap(), long);
        assert_eq!(encrypt_with(&ck, &"x".repeat(300), &nonce).unwrap().len(), 516);
        // Both sides get the same key; a changed byte fails.
        assert_eq!(conversation_key_local(TWO, &core::x_only_of(ONE).unwrap()).unwrap(), ck);
        let mut bad = p.to_string();
        bad.replace_range(60..61, if &p[60..61] == "A" { "B" } else { "A" });
        assert!(decrypt(&ck, &bad).is_err());
        assert!(encrypt(&ck, "").is_err());
        assert_eq!(padded_len(33), 64);
        assert_eq!(padded_len(257), 320);
    }

    #[test]
    fn wrapped_twice_and_opened_by_the_reader() {
        let (from_sk, to_sk) = (hex::encode(core::random32()), hex::encode(core::random32()));
        let (from, to) = (core::x_only_of(&from_sk).unwrap(), core::x_only_of(&to_sk).unwrap());
        let now = core::now();
        let r = rumor(&from, &to, "hi there", now).unwrap();
        let ck = conversation_key_local(&from_sk, &to).unwrap();
        let seal = sign_local(&from_sk, &seal_unsigned(&ck, &r, now).unwrap()).unwrap();
        assert!(verified(&seal));
        assert!(seal["created_at"].as_u64().unwrap() <= now);
        let w = wrap(&seal, &to, now).unwrap().signed().unwrap();
        assert!(verified(&w));
        assert_eq!((w["kind"].as_u64(), w["tags"].clone()), (Some(1059), json!([["p", to]])));
        assert_ne!(w["pubkey"].as_str(), Some(from.as_str()));
        // The reader: the wrap with the wrap's key, the seal with the sender's.
        let s: Value = serde_json::from_str(&decrypt(&conversation_key_local(&to_sk, w["pubkey"].as_str().unwrap()).unwrap(), w["content"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(s, seal);
        let inner: Value = serde_json::from_str(&decrypt(&conversation_key_local(&to_sk, &from).unwrap(), s["content"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(inner, r);
        assert!(inner.get("sig").is_none());
    }

    #[test]
    fn proof_of_work() {
        assert_eq!(zero_bits(&[0, 0, 0x0f, 0xff]), 20);
        assert_eq!(zero_bits(&[0x80]), 0);
        assert_eq!(pow_of_refusal("pow: difficulty 0 is less than the 16 this relay requires"), Some(16));
        assert_eq!(pow_of_refusal("blocked: pow 16"), None);
        assert_eq!(pow_of_refusal("pow: too low"), None);
        assert_eq!(pow_of_info(&json!({ "limitation": { "min_pow_difficulty": 12 } })), 12);
        assert_eq!(pow_of_info(&Value::Null), 0);
        let w = wrap(&json!({ "kind": 13 }), &core::x_only_of(TWO).unwrap(), core::now()).unwrap();
        let m = w.mined(12).unwrap();
        assert!(verified(&m));
        assert!(zero_bits(&hex::decode(m["id"].as_str().unwrap()).unwrap()) >= 12);
        let tags = m["tags"].as_array().unwrap();
        assert_eq!((tags[0].clone(), tags[1][0].clone(), tags[1][2].clone()), (json!(["p", core::x_only_of(TWO).unwrap()]), json!("nonce"), json!("12")));
        assert_eq!((m["content"].clone(), m["created_at"].clone()), (w.unsigned["content"].clone(), w.unsigned["created_at"].clone()));
        assert!(w.mined(MAX_POW + 1).unwrap_err().contains("more than keykin does"));
    }

    /// A relay on 127.0.0.1 that sends a login challenge and refuses wraps until logged in (when `auth`), says in its
    /// NIP-11 document that it wants `info_pow` bits, and refuses less than `pow` bits with "pow: …" (saying the number
    /// when `says`). It hands back the events it took, each with the key that logged in.
    async fn fake_relay(auth: bool, info_pow: u32, pow: u32, says: bool) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(Value, Option<String>)>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://127.0.0.1:{}", l.local_addr().unwrap().port());
        let took = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let kept = took.clone();
        let me = url.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut tcp, _)) = l.accept().await else { return };
                let mut head = [0u8; 2048];
                let n = tcp.peek(&mut head).await.unwrap_or(0);
                if !String::from_utf8_lossy(&head[..n]).to_lowercase().contains("upgrade: websocket") {
                    let _ = tcp.read(&mut head).await;
                    let body = json!({ "limitation": { "min_pow_difficulty": info_pow } }).to_string();
                    let _ = tcp.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/nostr+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                    continue;
                }
                let (kept, me) = (kept.clone(), me.clone());
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                    let mut who: Option<String> = None;
                    if auth {
                        ws.send(Message::text(json!(["AUTH", "chal-1"]).to_string())).await.unwrap();
                    }
                    while let Some(Ok(m)) = ws.next().await {
                        let Ok(v) = serde_json::from_str::<Value>(m.to_text().unwrap_or("")) else { continue };
                        let ev = &v[1];
                        let answer = match v[0].as_str() {
                            Some("AUTH") => {
                                let ok = verified(ev) && ev["kind"] == 22242 && ev["tags"].as_array().unwrap().iter().any(|t| t[0] == "challenge" && t[1] == "chal-1") && ev["tags"].as_array().unwrap().iter().any(|t| t[0] == "relay" && t[1] == me.as_str());
                                if ok {
                                    who = ev["pubkey"].as_str().map(str::to_string);
                                }
                                json!(["OK", ev["id"], ok, if ok { "" } else { "invalid: bad login" }])
                            }
                            Some("EVENT") if auth && who.is_none() => json!(["OK", ev["id"], false, "auth-required: you must auth"]),
                            Some("EVENT") if zero_bits(&hex::decode(ev["id"].as_str().unwrap()).unwrap()) < pow => {
                                let why = if says { format!("pow: difficulty 0 is less than the {pow} this relay requires") } else { "pow: too low".into() };
                                json!(["OK", ev["id"], false, why])
                            }
                            Some("EVENT") => {
                                kept.lock().unwrap().push((ev.clone(), who.clone()));
                                json!(["OK", ev["id"], verified(ev), ""])
                            }
                            _ => continue,
                        };
                        let _ = ws.send(Message::text(answer.to_string())).await;
                    }
                });
            }
        });
        (url, took)
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn a_relay_that_wants_a_login_and_work_gets_them_from_the_wrap_key() {
        block_on(async {
            let to = core::x_only_of(TWO).unwrap();
            let w = wrap(&json!({ "kind": 13 }), &to, core::now()).unwrap();
            let wrap_key = core::x_only_of(&w.sk).unwrap();
            // Logs in, then is told 12 bits in the refusal.
            let (url, took) = fake_relay(true, 0, 12, true).await;
            publish_one(&url, &w).await.unwrap();
            let (ev, who) = took.lock().unwrap()[0].clone();
            assert_eq!(who.as_deref(), Some(wrap_key.as_str()));
            assert_eq!(ev["pubkey"], json!(wrap_key));
            assert!(zero_bits(&hex::decode(ev["id"].as_str().unwrap()).unwrap()) >= 12);
            // Says 10 bits in its document only: mined before the first try.
            let (url, took) = fake_relay(false, 10, 10, false).await;
            publish_one(&url, &w).await.unwrap();
            assert_eq!(took.lock().unwrap().len(), 1);
            // Wants more than keykin does: refused, saying so.
            let (url, _) = fake_relay(false, 0, 30, true).await;
            assert!(publish_one(&url, &w).await.unwrap_err().contains("more than keykin does"));
            // Refuses without a number: its words.
            let (url, _) = fake_relay(false, 0, 30, false).await;
            assert_eq!(publish_one(&url, &w).await.unwrap_err(), "pow: too low");
        });
    }

    #[test]
    fn where_someone_reads_and_what_they_are_called() {
        let a = "aa".repeat(32);
        let ev = |kind: u64, at: u64, tags: Value, content: &str| json!({ "pubkey": a, "kind": kind, "created_at": at, "tags": tags, "content": content });
        let evs = vec![
            ev(10050, 1, json!([["relay", "wss://old.example"]]), ""),
            ev(10050, 2, json!([["relay", "wss://dm.example/"], ["relay", "https://not.a.relay"], ["relay", "wss://dm.example"]]), ""),
            ev(10002, 3, json!([["r", "wss://w.example", "write"], ["r", "wss://r.example"]]), ""),
            ev(0, 1, json!([]), r#"{"name":"al\nice","display_name":""}"#),
        ];
        assert_eq!(dm_relays(&evs, &a), vec!["wss://dm.example"]);
        assert_eq!(write_relays(&evs, &a), vec!["wss://w.example", "wss://r.example"]);
        assert_eq!(dm_relays(&evs[2..], &a), vec!["wss://r.example"]);
        assert!(dm_relays(&evs[3..], &a).is_empty());
        assert_eq!(display_name(&evs, &a).as_deref(), Some("alice"));
        assert_eq!(display_name(&evs, &"bb".repeat(32)), None);
    }
}
