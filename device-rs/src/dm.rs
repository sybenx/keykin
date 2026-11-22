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

/// The gift wrap (kind 1059) for `to`: the signed seal, encrypted and signed with a key made for this wrap alone.
pub fn wrap(seal: &Value, to: &str, now: u64) -> R<Value> {
    let sk = hex::encode(core::random32());
    let ck = conversation_key_local(&sk, to)?;
    let ev = json!({ "created_at": some_time_before(now), "kind": 1059, "tags": [["p", to]], "content": encrypt(&ck, &seal.to_string())? });
    sign_local(&sk, &ev)
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

/// The events one relay has for `filter`, up to its end of stored events, within a few seconds.
async fn fetch_one(relay: &str, filter: &Value) -> Vec<Value> {
    let Ok(mut ws) = connect(relay).await else { return vec![] };
    let mut got = vec![];
    if ws.send(Message::text(json!(["REQ", "kk", filter]).to_string())).await.is_ok() {
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        while let Ok(Some(Ok(m))) = tokio::time::timeout_at(until, ws.next()).await {
            let Ok(v) = serde_json::from_str::<Value>(m.to_text().unwrap_or("")) else { continue };
            match v[0].as_str() {
                Some("EVENT") if v[1] == "kk" && verified(&v[2]) => got.push(v[2].clone()),
                Some("EOSE" | "CLOSED") if v[1] == "kk" => break,
                _ => {}
            }
        }
    }
    let _ = ws.close(None).await;
    got
}

/// What all of `relays` have for `filter`, asked at once.
pub async fn fetch(relays: &[String], filter: Value) -> Vec<Value> {
    futures_util::future::join_all(relays.iter().map(|r| fetch_one(r, &filter))).await.into_iter().flatten().collect()
}

/// Leaves `ev` on one relay. Ok when it says it took it; its words when it refused.
pub async fn publish_one(relay: &str, ev: &Value) -> R<()> {
    let mut ws = connect(relay).await?;
    ws.send(Message::text(json!(["EVENT", ev]).to_string())).await.map_err(|e| e.to_string())?;
    let until = tokio::time::Instant::now() + Duration::from_secs(8);
    let r = loop {
        match tokio::time::timeout_at(until, ws.next()).await {
            Ok(Some(Ok(m))) => {
                let Ok(v) = serde_json::from_str::<Value>(m.to_text().unwrap_or("")) else { continue };
                if v[0] == "OK" && v[1] == ev["id"] {
                    break if v[2] == true { Ok(()) } else { Err(v[3].as_str().filter(|s| !s.is_empty()).unwrap_or("refused").to_string()) };
                }
            }
            Ok(_) => break Err("closed the connection".into()),
            Err(_) => break Err("didn’t answer".into()),
        }
    };
    let _ = ws.close(None).await;
    r
}

/// Leaves `ev` on each of `relays`, all at once: (relay, how it went).
pub async fn publish(relays: &[String], ev: &Value) -> Vec<(String, R<()>)> {
    let rs = futures_util::future::join_all(relays.iter().map(|r| publish_one(r, ev))).await;
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
        let w = wrap(&seal, &to, now).unwrap();
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
        assert_eq!(dm_relays(&evs[2..], &a), vec!["wss://r.example"]);
        assert!(dm_relays(&evs[3..], &a).is_empty());
        assert_eq!(display_name(&evs, &a).as_deref(), Some("alice"));
        assert_eq!(display_name(&evs, &"bb".repeat(32)), None);
    }
}
