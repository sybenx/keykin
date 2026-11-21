// Being a Keykin device (~/keykin/SPEC.md): the device side of §3 (signing), §4 (member
// keys and signed requests), §5 (sealed values), §7 and §8b (joining), §8a (a shared secret for
// NIP-44) and §11.2 (the account named in every request). It follows ~/keykin/src/device.ts, the
// Terminal device's code, step for step. The FROST math is Keykin's own crate (~/keykin/frost).
//
// Lifted from Marble on Mac (marble-desktop src-tauri/src/keykin.rs, its box-authority branch) so that
// every desktop device shares one copy (the 2026-11-20 direction: one device core, library first).
// Nothing here keeps anything: the caller holds the `Account` (`store.rs` for the command line) and
// saves it again after a call that may have moved it to a new epoch.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub type R<T> = Result<T, String>;

// --- Bytes, hex, canonical JSON ------------------------------------------------------------

pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("random");
    b
}

pub fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn unhex<const N: usize>(h: &str, what: &str) -> R<[u8; N]> {
    if !is_hex(h, N) {
        return Err(format!("{what}: expected {N} bytes of hex"));
    }
    let v = hex::decode(h).map_err(|e| e.to_string())?;
    v.try_into().map_err(|_| format!("{what}: expected {N} bytes"))
}

/// RFC 8785 canonical JSON, as Keykin's `jcs` makes it: keys sorted by UTF-16 code units, safe
/// integers only, strings as JSON.stringify writes them (serde_json escapes the same way).
pub fn canon(v: &Value) -> R<String> {
    Ok(match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            const MAX: i128 = (1 << 53) - 1;
            let i = n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)).ok_or("JCS: numbers are safe integers")?;
            if !(-MAX..=MAX).contains(&i) {
                return Err("JCS: numbers are safe integers".into());
            }
            i.to_string()
        }
        Value::String(s) => serde_json::to_string(s).map_err(|e| e.to_string())?,
        Value::Array(a) => format!("[{}]", a.iter().map(canon).collect::<R<Vec<_>>>()?.join(",")),
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let parts = keys.iter().map(|k| Ok(format!("{}:{}", serde_json::to_string(k).map_err(|e| e.to_string())?, canon(&o[*k])?))).collect::<R<Vec<_>>>()?;
            format!("{{{}}}", parts.join(","))
        }
    })
}

/// A Nostr event's id (NIP-01), from `pubkey`, `created_at`, `kind`, `tags` and `content`.
pub fn event_id(ev: &Value) -> R<String> {
    let arr = json!([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]);
    if !ev["pubkey"].is_string() || !ev["created_at"].is_u64() || !ev["kind"].is_u64() || !ev["tags"].is_array() || !ev["content"].is_string() {
        return Err("not an event".into());
    }
    Ok(hex::encode(sha(&[serde_json::to_string(&arr).map_err(|e| e.to_string())?.as_bytes()])))
}

// --- Scalars and points --------------------------------------------------------------------

pub fn scalar(h: &str, what: &str) -> R<Scalar> {
    let b = unhex::<32>(h, what)?;
    Option::<Scalar>::from(Scalar::from_repr(b.into())).ok_or_else(|| format!("{what}: out of range"))
}
pub fn scalar_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}
pub fn point(h: &str, what: &str) -> R<ProjectivePoint> {
    let b = unhex::<33>(h, what)?;
    if b[0] != 2 && b[0] != 3 {
        return Err(format!("{what}: expected a compressed point"));
    }
    PublicKey::from_sec1_bytes(&b).map(|p| p.to_projective()).map_err(|_| format!("{what}: not on the curve"))
}
pub fn comp_hex(p: &ProjectivePoint) -> R<String> {
    let e: EncodedPoint = p.to_affine().to_encoded_point(true);
    if e.is_identity() {
        return Err("the identity has no encoding".into());
    }
    Ok(hex::encode(e.as_bytes()))
}
fn x_of(p: &ProjectivePoint) -> R<[u8; 32]> {
    let h = comp_hex(p)?;
    unhex::<32>(&h[2..], "x")
}
pub fn lift_x(x: &str) -> R<ProjectivePoint> {
    point(&format!("02{x}"), "x-only key")
}
/// A FROST identifier for an index: the index as a 32-byte big-endian scalar.
pub fn id_hex(i: u32) -> String {
    format!("{i:064x}")
}
/// The Lagrange coefficient at 0 for `i`, when signing together with `other`: other / (other - i).
fn lagrange(i: u32, other: u32) -> R<Scalar> {
    if i == other {
        return Err("repeated index".into());
    }
    let den = Scalar::from(other as u64) - Scalar::from(i as u64);
    let inv = Option::<Scalar>::from(den.invert()).ok_or("no inverse")?;
    Ok(Scalar::from(other as u64) * inv)
}

// --- Member keys and signed requests (§4) ----------------------------------------------------

/// This device: its member key (secp256k1, x-only), separate from its piece, and its name.
#[derive(Clone, Serialize, Deserialize)]
pub struct Me {
    pub sk: String,
    pub key: String,
    pub name: String,
}

impl Drop for Me {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

pub fn x_only_of(sk: &str) -> R<String> {
    let k = k256::schnorr::SigningKey::from_bytes(&unhex::<32>(sk, "key")?).map_err(|_| "bad key")?;
    Ok(hex::encode(k.verifying_key().to_bytes()))
}

pub fn new_me(name: &str) -> Me {
    loop {
        let sk = hex::encode(random32());
        if let Ok(key) = x_only_of(&sk) {
            return Me { sk, key, name: name.into() };
        }
    }
}

/// BIP-340 by `sk` over a 32-byte message.
pub fn schnorr_sign(sk: &str, msg: &[u8; 32]) -> R<String> {
    let k = k256::schnorr::SigningKey::from_bytes(&unhex::<32>(sk, "key")?).map_err(|_| "bad key")?;
    let sig = k.sign_raw(msg, &random32()).map_err(|e| e.to_string())?;
    Ok(hex::encode(sig.to_bytes()))
}

pub fn schnorr_verify(x: &str, msg: &[u8; 32], sig: &str) -> bool {
    let (Ok(x), Ok(s)) = (unhex::<32>(x, "key"), unhex::<64>(sig, "sig")) else { return false };
    let (Ok(vk), Ok(sig)) = (k256::schnorr::VerifyingKey::from_bytes(&x), k256::schnorr::Signature::try_from(&s[..])) else { return false };
    vk.verify_raw(msg, &sig).is_ok()
}

/// A request `{ body, key, sig }`: `body` with `ts` and a random `id`, signed over SHA-256(JCS(body)).
pub fn seal_request(mut body: Value, me: &Me, now: u64) -> R<Value> {
    let o = body.as_object_mut().ok_or("a request body is an object")?;
    o.insert("ts".into(), json!(now));
    o.insert("id".into(), json!(hex::encode(&random32()[..16])));
    let bytes = canon(&body)?;
    let sig = schnorr_sign(&me.sk, &sha(&[bytes.as_bytes()]))?;
    Ok(json!({ "body": body, "key": me.key, "sig": sig }))
}

// --- Sealed values (§5) ------------------------------------------------------------------------

fn seal_key(sk: &str, peer: &str) -> R<[u8; 32]> {
    let shared = lift_x(peer)? * scalar(sk, "key")?;
    Ok(sha(&[b"keykin2-seal", &x_of(&shared)?]))
}

#[cfg_attr(not(test), allow(dead_code))]
/// A secret sealed to `peer` for `why` (XChaCha20-Poly1305, the purpose as associated data). Hex.
pub fn seal_to(sk: &str, peer: &str, why: &str, secret_hex: &str) -> R<String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let key = seal_key(sk, peer)?;
    let nonce: [u8; 24] = random32()[..24].try_into().unwrap();
    let c = chacha20poly1305::XChaCha20Poly1305::new((&key).into());
    let msg = hex::decode(secret_hex).map_err(|e| e.to_string())?;
    let ct = c.encrypt((&nonce).into(), Payload { msg: &msg, aad: why.as_bytes() }).map_err(|_| "seal failed")?;
    Ok(hex::encode([&nonce[..], &ct].concat()))
}

pub fn open_from(sk: &str, peer: &str, why: &str, boxed: &str) -> R<String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let b = hex::decode(boxed).map_err(|_| "bad_seal")?;
    if b.len() < 24 + 16 {
        return Err("bad_seal".into());
    }
    let key = seal_key(sk, peer)?;
    let c = chacha20poly1305::XChaCha20Poly1305::new((&key).into());
    let mut out = c.decrypt(b[..24].into(), Payload { msg: &b[24..], aad: why.as_bytes() }).map_err(|_| "bad_seal")?;
    let h = hex::encode(&out);
    out.zeroize();
    Ok(h)
}

// --- A piece and a signing round (§3) -----------------------------------------------------------

/// This device's piece: the account's commitment `[a0·G, a1·G]`, its index, and `f(i)`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Piece {
    pub c: [String; 2],
    pub i: u32,
    pub share: String,
}

impl Drop for Piece {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl Piece {
    fn cj(&self) -> String {
        serde_json::to_string(&self.c).unwrap()
    }
    /// `C0 + C1·i`, the point this piece must be.
    fn point(&self) -> R<ProjectivePoint> {
        Ok(point(&self.c[0], "C0")? + point(&self.c[1], "C1")? * Scalar::from(self.i as u64))
    }
    fn check(&self, npub: &str) -> R<()> {
        if &self.c[0][2..] != npub || !self.c[0].starts_with("02") {
            return Err("wrong_account".into());
        }
        if ProjectivePoint::GENERATOR * scalar(&self.share, "share")? != self.point()? {
            return Err("bad_piece".into());
        }
        Ok(())
    }
}

/// The commit as it travels: `{ i, D, E }` with `i` a number.
fn wire_commit(c: &Value) -> R<(u32, String, String)> {
    let i = c["i"].as_u64().ok_or("bad_commit")? as u32;
    let (d, e) = (c["D"].as_str().ok_or("bad_commit")?, c["E"].as_str().ok_or("bad_commit")?);
    Ok((i, d.into(), e.into()))
}
fn commits_json(cs: &[&(u32, String, String)]) -> String {
    serde_json::to_string(&cs.iter().map(|(i, d, e)| json!({ "i": id_hex(*i), "D": d, "E": e })).collect::<Vec<_>>()).unwrap()
}

/// The asker's first step: fresh nonces (kept here, used once) and the commit to send.
struct Round {
    nonces: String,
    commit: (u32, String, String),
}

impl Drop for Round {
    fn drop(&mut self) {
        self.nonces.zeroize();
    }
}

fn ask(p: &Piece, msg: &str) -> R<Round> {
    // The hedged random input: SHA-256(fresh randomness ‖ share ‖ context), as Keykin's frost.ts.
    let context = sha(&[b"keykin2-round", msg.as_bytes()]);
    let mut share = unhex::<32>(&p.share, "share")?;
    let hedge = hex::encode(sha(&[&random32(), &share, &context]));
    share.zeroize();
    let r: Value = serde_json::from_str(&keykin_frost::commit(&p.cj(), &id_hex(p.i), &p.share, &hedge)?).map_err(|e| e.to_string())?;
    let c = &r["commit"];
    Ok(Round { nonces: r["nonces"].as_str().ok_or("no nonces")?.into(), commit: (p.i, c["D"].as_str().ok_or("bad")?.into(), c["E"].as_str().ok_or("bad")?.into()) })
}

/// The asker's last step: check the helper's partial, add our own, and return the BIP-340 signature.
fn finish(p: &Piece, npub: &str, msg: &str, mine: Round, theirs: &Value, z: &str) -> R<String> {
    let t = wire_commit(theirs)?;
    if t.0 == p.i {
        return Err("same_piece".into());
    }
    let commits = commits_json(&[&mine.commit, &t]);
    if !keykin_frost::verify_partial(&p.cj(), msg, &commits, &id_hex(t.0), z)? {
        return Err("bad_partial".into());
    }
    let my_z = keykin_frost::sign(&p.cj(), &id_hex(p.i), &p.share, &mine.nonces, msg, &commits)?;
    let partials = serde_json::to_string(&json!([[id_hex(p.i), my_z], [id_hex(t.0), z]])).unwrap();
    let sig = keykin_frost::aggregate(&p.cj(), msg, &commits, &partials)?;
    if !schnorr_verify(npub, &unhex::<32>(msg, "id")?, &sig) {
        return Err("bad_signature".into());
    }
    Ok(sig)
}

// --- A shared secret with another key (§8a), and NIP-44's conversation key ----------------------

/// This piece's part for `peer`: λ_i · s_i · Q, when the other piece is `other`.
pub fn ecdh_part(p: &Piece, other: u32, peer: &str) -> R<String> {
    comp_hex(&(lift_x(peer)? * (lagrange(p.i, other)? * scalar(&p.share, "share")?)))
}
fn ecdh_shared(a: &str, b: &str) -> R<[u8; 32]> {
    let s = point(a, "part")? + point(b, "part")?;
    x_of(&s).map_err(|_| "bad_part".into())
}
pub fn nip44_key(shared_x: &[u8; 32]) -> [u8; 32] {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared_x);
    prk.into()
}

// --- The account as this device holds it ---------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    /// Where the box is (from the join text).
    pub addr: String,
    pub box_key: String,
    /// The account's id: its npub, as hex.
    pub npub: String,
    pub piece: Piece,
    pub epoch: u64,
}

/// What the join text says: `{ keykin: 2, join: { addr, boxKey, npub } }`.
pub struct JoinText {
    pub addr: String,
    pub box_key: String,
    pub npub: String,
}

pub fn read_join(text: &str) -> R<JoinText> {
    let bad = || "That isn't a join code. Copy the whole code your phone or account page shows.".to_string();
    let v: Value = serde_json::from_str(text.trim()).map_err(|_| bad())?;
    let j = &v["join"];
    let (addr, box_key, npub) = (j["addr"].as_str().ok_or_else(bad)?, j["boxKey"].as_str().ok_or_else(bad)?, j["npub"].as_str().ok_or_else(bad)?);
    if v["keykin"] != json!(2) || !(addr.starts_with("http://") || addr.starts_with("https://")) || !is_hex(box_key, 32) || !is_hex(npub, 32) {
        return Err(bad());
    }
    Ok(JoinText { addr: addr.trim_end_matches('/').into(), box_key: box_key.into(), npub: npub.into() })
}

/// The invite a device in the account adds (§8b). This device has no chip key (that needs Apple's
/// developer signing), so it can sign and read but not change the account, like a phone with no
/// fingerprint set up.
pub fn invite(me: &Me) -> String {
    json!({ "keykin": 2, "invite": { "key": me.key, "name": me.name } }).to_string()
}

// --- Talking to the box ------------------------------------------------------------------------------

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A refusal from the box (its stable code), a refusal with the box's reason in plain words (`needs_tap`,
/// `needs_fingerprint`, `dated_ahead`: Keykin SPEC 11.6, The tap), or a failure to reach it.
#[derive(Debug)]
pub enum Failure {
    Refused(String),
    Said { code: String, why: String },
    Unreachable(String),
}

impl Failure {
    pub fn code(&self) -> &str {
        match self {
            Failure::Refused(c) | Failure::Said { code: c, .. } => c,
            Failure::Unreachable(_) => "unreachable",
        }
    }
    /// Never done by accident (level 2, Keykin SPEC 11.6, The tap): the box signs it only behind the phone's
    /// fingerprint, which this device does not have. An account change's `needs_fingerprint` carries no words.
    pub fn phone_only(&self) -> bool {
        matches!(self, Failure::Said { code, .. } if code == "needs_fingerprint" || code == "no_chip_key")
    }
    /// The box's own words, when it gave some.
    pub fn why(&self) -> Option<&str> {
        match self {
            Failure::Said { why, .. } => Some(why),
            _ => None,
        }
    }
    /// The box no longer takes this device: it was blocked, or dropped by a cycle.
    pub fn removed(&self) -> bool {
        matches!(self.code(), "blocked" | "unknown_member" | "unknown_account")
    }
    /// What went wrong underneath, for the self-test's log.
    pub fn detail(&self) -> &str {
        match self {
            Failure::Refused(c) | Failure::Said { code: c, .. } => c,
            Failure::Unreachable(e) => e,
        }
    }
    /// In plain words, for the box.
    pub fn words(&self) -> String {
        match self {
            Failure::Unreachable(_) => "Can’t reach your box right now.".into(),
            Failure::Said { why, .. } if self.phone_only() => format!("{}. {FROM_PHONE}", why.trim_end_matches(['.', ' '])),
            Failure::Said { why, .. } => why.clone(),
            Failure::Refused(c) => match c.as_str() {
                "denied" => "You said no. Nothing was signed.".into(),
                "needs_tap" => "Your box asks for your Yes before signing this.".into(),
                "blocked" => "This device was blocked from your account.".into(),
                "unknown_member" | "unknown_account" => "This device isn’t in your account any more.".into(),
                "wrong_account" => "That join code is for another account.".into(),
                "wrong_code" => "That code isn’t right, or it ran out. Press Sign in again.".into(),
                "not_approved" => "Your account page hasn’t approved this device yet.".into(),
                "no_welcome" | "gone" => "Your box has nothing waiting for this device. Add it again from your phone, then paste the new code.".into(),
                "bad_seal" => "That join code was made for another invite. Add this device again from your phone.".into(),
                other => format!("Your box said no ({other})."),
            },
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.words())
    }
}

fn refused(e: impl Into<String>) -> Failure {
    Failure::Refused(e.into())
}

/// Carries a signed request to the box (`POST <addr>/keykin`) and returns its answer as it came.
async fn post(addr: &str, req: &Value) -> Result<Value, Failure> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build().map_err(|e| Failure::Unreachable(e.to_string()))?;
    let r = client.post(format!("{addr}/keykin")).json(req).send().await.map_err(|e| Failure::Unreachable(e.to_string()))?;
    r.json::<Value>().await.map_err(|e| Failure::Unreachable(e.to_string()))
}

/// The box's error answer as a failure, with its `why` when it gave one (cleaned: no control characters, at most 300).
fn failure(r: &Value, code: &str) -> Failure {
    let why: String = r["why"].as_str().unwrap_or("").chars().map(|c| if c.is_control() { ' ' } else { c }).take(300).collect();
    match why.trim() {
        "" => refused(code),
        w => Failure::Said { code: code.into(), why: w.into() },
    }
}

async fn call(addr: &str, body: Value, me: &Me) -> Result<Value, Failure> {
    let r = post(addr, &seal_request(body, me, now()).map_err(refused)?).await?;
    match r.get("error").and_then(|e| e.as_str()) {
        Some(e) => Err(failure(&r, e)),
        None => Ok(r),
    }
}

/// The new device's side of §7: collect both halves of its piece from the box and check the result.
pub async fn join(me: &Me, j: &JoinText) -> Result<Account, Failure> {
    join_with(me, &j.addr, Some(j), None).await
}

/// The same, for a device added through the account page (§7, §11.6): its welcome needs the approval code,
/// and the PKCE verifier its challenge was made from. With no join text (the six digits typed in, with the
/// page's address), the box finds the account by this device's key and names itself in its answer.
pub async fn join_with(me: &Me, addr: &str, j: Option<&JoinText>, approval: Option<(&str, Option<&str>)>) -> Result<Account, Failure> {
    let mut body = json!({ "op": "welcome" });
    if let Some(j) = j {
        body["account"] = json!(j.npub);
    }
    if let Some((code, verifier)) = approval {
        body["code"] = json!(code);
        if let Some(v) = verifier {
            body["verifier"] = json!(v);
        }
    }
    let r = call(addr, body, me).await?;
    let npub = match j {
        Some(j) if r["npub"].as_str() != Some(&j.npub) => return Err(refused("wrong_account")),
        Some(j) => j.npub.clone(),
        None => r["npub"].as_str().filter(|n| is_hex(n, 32)).ok_or_else(|| refused("wrong_account"))?.to_string(),
    };
    let box_key = match j {
        Some(j) => j.box_key.clone(),
        None => r["boxKey"].as_str().filter(|k| is_hex(k, 32)).ok_or_else(|| refused("bad_welcome"))?.to_string(),
    };
    let j = &JoinText { addr: addr.trim_end_matches('/').to_string(), box_key, npub };
    let c: [String; 2] = serde_json::from_value(r["commitment"].clone()).map_err(|_| refused("bad_commitment"))?;
    let i = r["i"].as_u64().ok_or_else(|| refused("bad_index"))? as u32;
    let from = r["from"].as_str().ok_or_else(|| refused("bad_welcome"))?;
    let sigmas = [
        open_from(&me.sk, &j.box_key, "repair-sigma", r["box"].as_str().unwrap_or("")).map_err(refused)?,
        open_from(&me.sk, from, "repair-sigma", r["device"].as_str().unwrap_or("")).map_err(refused)?,
    ];
    let mut piece = Piece { c, i, share: String::new() };
    piece.share = keykin_frost::repair_step3(&piece.cj(), &serde_json::to_string(&sigmas).unwrap(), &id_hex(i)).map_err(|_| refused("repair_failed"))?;
    piece.check(&j.npub).map_err(refused)?;
    Ok(Account { addr: j.addr.clone(), box_key: j.box_key.clone(), npub: j.npub.clone(), piece, epoch: r["epoch"].as_u64().unwrap_or(0) })
}

/// A request that depends on the current pieces. If the keys were cycled while this device was away, the
/// box answers `stale` with the changes it missed; they are applied to `a` and the request is asked
/// again once. `a` changes in place, so the caller saves it afterwards.
async fn current(me: &Me, a: &mut Account, body: &mut (dyn FnMut(&Account) -> R<Value> + Send)) -> Result<Value, Failure> {
    for tries in 0.. {
        let mut b = body(a).map_err(refused)?;
        b["epoch"] = json!(a.epoch);
        b["account"] = json!(a.npub);
        let r = post(&a.addr, &seal_request(b, me, now()).map_err(refused)?).await?;
        let err = r.get("error").and_then(|e| e.as_str());
        if err == Some("stale") && tries == 0 && r["catchups"].is_array() {
            catch_up(me, a, &r).map_err(refused)?;
            call(&a.addr, json!({ "op": "caught_up", "account": a.npub }), me).await?;
            continue;
        }
        if let Some(e) = err {
            return Err(failure(&r, e));
        }
        return Ok(r);
    }
    unreachable!()
}

fn catch_up(me: &Me, a: &mut Account, r: &Value) -> R<()> {
    let mut share = scalar(&a.piece.share, "share")?;
    for c in r["catchups"].as_array().unwrap() {
        let delta = open_from(&me.sk, c["from"].as_str().unwrap_or(""), "cycle", c["sealed"].as_str().unwrap_or(""))?;
        share += scalar(&delta, "change")?;
    }
    let c: [String; 2] = serde_json::from_value(r["commitment"].clone()).map_err(|_| "bad_commitment")?;
    let next = Piece { c, i: a.piece.i, share: scalar_hex(&share) };
    next.check(&a.npub)?;
    a.piece = next;
    a.epoch = r["epoch"].as_u64().ok_or("bad_epoch")?;
    Ok(())
}

/// Where a level 2 event is done, said by this device after the box's words.
pub const FROM_PHONE: &str = "Do this from your phone.";

/// Signs an event as the account (§3), asking the person first when the box wants that. The box decides what
/// is hard to undo (Keykin SPEC 11.6, The tap), and its answer carries the level, so this device has no rules of its
/// own about it:
///
/// - Level 1, `needs_tap` with its question: `ask(why, false)` puts it to the person, and on Yes the same request
///   goes again with `tapped`. On No nothing is signed (`denied`).
/// - Level 2, `needs_fingerprint` (or `no_chip_key`) with its question: never done by accident, and only on the
///   phone, behind its fingerprint. `ask(why, true)` shows the box's words and that it is done from the phone, with
///   no Yes; whatever comes back, this device sends nothing more, and the box's refusal is the answer.
pub async fn sign_asking<A, F>(me: &Me, a: &mut Account, ev: &Value, ask: A) -> Result<Value, Failure>
where
    A: FnOnce(String, bool) -> F,
    F: std::future::Future<Output = bool>,
{
    match sign_event(me, a, ev, false).await {
        // Its words, or general ones from a box from before it said why.
        Err(f) if f.code() == "needs_tap" => {
            if !ask(f.words(), false).await {
                return Err(refused("denied"));
            }
            sign_event(me, a, ev, true).await
        }
        Err(f) if f.phone_only() => {
            let _ = ask(f.why().unwrap_or_default().to_string(), true).await;
            Err(f)
        }
        r => r,
    }
}

/// Signs an event as the account (§3): one round trip with the box. `ev` has `created_at`, `kind`,
/// `tags` and `content`; its `pubkey` is the account's. `tapped`: the person said Yes to this event here.
pub async fn sign_event(me: &Me, a: &mut Account, ev: &Value, tapped: bool) -> Result<Value, Failure> {
    let unsigned = json!({ "pubkey": a.npub, "created_at": ev["created_at"], "kind": ev["kind"], "tags": ev["tags"], "content": ev["content"] });
    let id = event_id(&unsigned).map_err(refused)?;
    let mut round: Option<Round> = None;
    let r = current(me, a, &mut |a| {
        let mine = ask(&a.piece, &id)?;
        let (i, d, e) = mine.commit.clone();
        round = Some(mine);
        let mut body = json!({ "op": "sign", "event": unsigned, "commit": { "i": i, "D": d, "E": e } });
        if tapped {
            body["tapped"] = json!(true);
        }
        Ok(body)
    })
    .await?;
    if r["id"].as_str() != Some(&id) {
        return Err(refused("wrong_id"));
    }
    let sig = finish(&a.piece, &a.npub, &id, round.take().ok_or_else(|| refused("no round"))?, &r["commit"], r["z"].as_str().unwrap_or("")).map_err(refused)?;
    let mut out = unsigned;
    out["id"] = json!(id);
    out["sig"] = json!(sig);
    Ok(out)
}

/// The NIP-44 conversation key with `peer` (x-only hex), made with the box. The key is never whole.
pub async fn conversation_key(me: &Me, a: &mut Account, peer: &str) -> Result<[u8; 32], Failure> {
    if !is_hex(peer, 32) {
        return Err(refused("bad_peer"));
    }
    let r = current(me, a, &mut |_| Ok(json!({ "op": "ecdh", "peer": peer }))).await?;
    let other = r["i"].as_u64().ok_or_else(|| refused("bad_part"))? as u32;
    let mine = ecdh_part(&a.piece, other, peer).map_err(refused)?;
    let x = ecdh_shared(&mine, r["part"].as_str().unwrap_or("")).map_err(refused)?;
    Ok(nip44_key(&x))
}

/// The account's members as the box lists them, its epoch and its id.
pub async fn members(me: &Me, a: &Account) -> Result<Value, Failure> {
    call(&a.addr, json!({ "op": "members", "account": a.npub }), me).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    fn s(n: u64) -> Scalar {
        Scalar::from(n)
    }

    /// A line f(x) = a0 + a1·x with a0·G of even y, as Keykin deals one (frost.ts `deal`).
    fn deal() -> (Scalar, Scalar, [String; 2]) {
        loop {
            let a0 = scalar(&hex::encode(random32()), "a0").unwrap();
            let p = ProjectivePoint::GENERATOR * a0;
            if !comp_hex(&p).unwrap().starts_with("02") {
                continue;
            }
            let a1 = scalar(&hex::encode(random32()), "a1").unwrap();
            return (a0, a1, [comp_hex(&p).unwrap(), comp_hex(&(ProjectivePoint::GENERATOR * a1)).unwrap()]);
        }
    }
    fn piece_at(a0: Scalar, a1: Scalar, c: &[String; 2], i: u32) -> Piece {
        Piece { c: c.clone(), i, share: scalar_hex(&(a0 + a1 * s(i as u64))) }
    }

    #[test]
    fn canonical_json_matches_keykin() {
        let v = json!({ "b": 1, "a": [true, null, "x\n\"y\u{1}"], "aa": { "z": -3, "y": "é" } });
        assert_eq!(canon(&v).unwrap(), r#"{"a":[true,null,"x\n\"y\u0001"],"aa":{"y":"é","z":-3},"b":1}"#);
        assert!(canon(&json!(1.5)).is_err());
        assert!(canon(&json!(9007199254740992u64)).is_err());
    }

    #[test]
    fn event_ids_are_nip01() {
        // nostr-tools' getEventHash for this event.
        let ev = json!({ "pubkey": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "created_at": 1, "kind": 1, "tags": [["t", "a"]], "content": "hi \"there\"\n" });
        let want = hex::encode(sha(&[br#"[0,"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",1,1,[["t","a"]],"hi \"there\"\n"]"#]));
        assert_eq!(event_id(&ev).unwrap(), want);
    }

    #[test]
    fn requests_verify() {
        let me = new_me("Mac");
        let r = seal_request(json!({ "op": "members", "account": "00" }), &me, 100).unwrap();
        let bytes = canon(&r["body"]).unwrap();
        assert!(schnorr_verify(&me.key, &sha(&[bytes.as_bytes()]), r["sig"].as_str().unwrap()));
        assert_eq!(r["body"]["ts"], json!(100));
        assert!(is_hex(r["body"]["id"].as_str().unwrap(), 16));
    }

    #[test]
    fn seals_open_both_ways_and_bind_the_purpose() {
        let (a, b) = (new_me("a"), new_me("b"));
        let boxed = seal_to(&a.sk, &b.key, "repair-sigma", &"11".repeat(32)).unwrap();
        assert_eq!(open_from(&b.sk, &a.key, "repair-sigma", &boxed).unwrap(), "11".repeat(32));
        assert!(open_from(&b.sk, &a.key, "cycle", &boxed).is_err());
    }

    #[test]
    fn two_pieces_sign_and_make_a_shared_secret() {
        let (a0, a1, c) = deal();
        let npub = c[0][2..].to_string();
        let (mac, boxp) = (piece_at(a0, a1, &c, 3), piece_at(a0, a1, &c, 2));
        mac.check(&npub).unwrap();
        // A round as the box answers it (round.ts `answer`).
        let msg = hex::encode(random32());
        let mine = ask(&mac, &msg).unwrap();
        let theirs = ask(&boxp, &msg).unwrap();
        let commits = commits_json(&[&mine.commit, &theirs.commit]);
        let z = keykin_frost::sign(&boxp.cj(), &id_hex(2), &boxp.share, &theirs.nonces, &msg, &commits).unwrap();
        let tc = json!({ "i": 2, "D": theirs.commit.1, "E": theirs.commit.2 });
        let sig = finish(&mac, &npub, &msg, mine, &tc, &z).unwrap();
        assert!(schnorr_verify(&npub, &unhex::<32>(&msg, "m").unwrap(), &sig));
        // ECDH: the two parts add up to nsec·Q.
        let peer = new_me("peer");
        let part_mac = ecdh_part(&mac, 2, &peer.key).unwrap();
        let part_box = ecdh_part(&boxp, 3, &peer.key).unwrap();
        let x = ecdh_shared(&part_mac, &part_box).unwrap();
        let whole = lift_x(&peer.key).unwrap() * a0;
        assert_eq!(x, x_of(&whole).unwrap());
        // ... and the peer's side gets the same: its secret times the account's key.
        let theirs = point(&c[0], "C0").unwrap() * scalar(&peer.sk, "k").unwrap();
        assert_eq!(x, x_of(&theirs).unwrap());
    }

    #[test]
    fn a_wrong_piece_is_refused() {
        let (a0, a1, c) = deal();
        let mut p = piece_at(a0, a1, &c, 3);
        p.share = scalar_hex(&(scalar(&p.share, "s").unwrap() + s(1)));
        assert!(p.check(&c[0][2..]).is_err());
    }

    /// A box on 127.0.0.1 holding piece 2, for `answers` requests: it asks about every event (`needs_tap` with `why`,
    /// or with none when `why` is None) until a request says `tapped`, then signs. What it was sent comes back, each
    /// request whole (`body`, `key`, `sig`, and `fp` if one came).
    fn fake_box(why: Option<&'static str>, answers: usize) -> (Account, std::thread::JoinHandle<Vec<Value>>) {
        fake_box_with(why, answers, None)
    }
    /// The same, but at level 2 when `refusal` is set: the box answers that code (`needs_fingerprint`, `no_chip_key`)
    /// with `why` unless the request carries `fp`, whatever `tapped` says, as the Keykin box does.
    fn fake_box_with(why: Option<&'static str>, answers: usize, refusal: Option<&'static str>) -> (Account, std::thread::JoinHandle<Vec<Value>>) {
        use std::io::{Read, Write};
        let (a0, a1, c) = deal();
        let npub = c[0][2..].to_string();
        let boxp = piece_at(a0, a1, &c, 2);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::thread::spawn(move || {
            let mut seen = vec![];
            for _ in 0..answers {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = vec![];
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = s.read(&mut chunk).unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let len: usize = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                        if buf.len() >= at + 4 + len {
                            break serde_json::from_slice::<Value>(&buf[at + 4..at + 4 + len]).unwrap();
                        }
                    }
                };
                let b = body["body"].clone();
                let answer = if let (Some(code), None) = (refusal, body.get("fp")) {
                    json!({ "error": code, "why": why.unwrap_or("") })
                } else if refusal.is_none() && b["tapped"] != json!(true) {
                    match why {
                        Some(w) => json!({ "error": "needs_tap", "why": w }),
                        None => json!({ "error": "needs_tap" }),
                    }
                } else {
                    // A round as the box answers it (round.ts `answer`).
                    let id = event_id(&b["event"]).unwrap();
                    let theirs = ask(&boxp, &id).unwrap();
                    let mine = wire_commit(&b["commit"]).unwrap();
                    let z = keykin_frost::sign(&boxp.cj(), &id_hex(2), &boxp.share, &theirs.nonces, &id, &commits_json(&[&mine, &theirs.commit])).unwrap();
                    json!({ "ok": true, "id": id, "commit": { "i": 2, "D": theirs.commit.1, "E": theirs.commit.2 }, "z": z })
                };
                seen.push(body);
                let text = answer.to_string();
                write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len()).unwrap();
            }
            seen
        });
        let a = Account { addr, box_key: "ab".repeat(32), npub, piece: piece_at(a0, a1, &c, 3), epoch: 0 };
        (a, seen)
    }
    fn follows_emptied() -> Value {
        json!({ "created_at": 1_800_000_000u64, "kind": 3, "tags": [], "content": "" })
    }

    #[test]
    fn the_box_asks_and_yes_sends_it_again_with_tapped() {
        let me = new_me("Marble on Mac");
        let (mut a, seen) = fake_box(Some("Empty your follow list"), 2);
        let asked = std::sync::Mutex::new(vec![]);
        let ev = block_on(sign_asking(&me, &mut a, &follows_emptied(), |why, phone| {
            asked.lock().unwrap().push((why, phone));
            async { true }
        }))
        .unwrap();
        assert_eq!(*asked.lock().unwrap(), vec![("Empty your follow list".to_string(), false)]);
        assert!(schnorr_verify(&a.npub, &unhex::<32>(ev["id"].as_str().unwrap(), "id").unwrap(), ev["sig"].as_str().unwrap()));
        let seen = seen.join().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0]["body"].get("tapped").is_none(), "the first request says nothing of a Yes");
        assert_eq!(seen[1]["body"]["tapped"], json!(true));
        assert_eq!(seen[0]["body"]["event"], seen[1]["body"]["event"], "the same request again");
    }

    #[test]
    fn no_leaves_nothing_signed() {
        let me = new_me("Marble on Mac");
        let (mut a, seen) = fake_box(Some("Empty your follow list"), 1);
        let r = block_on(sign_asking(&me, &mut a, &follows_emptied(), |_, _| async { false }));
        let f = r.err().unwrap();
        assert_eq!(f.code(), "denied");
        assert_eq!(f.words(), "You said no. Nothing was signed.");
        let seen = seen.join().unwrap();
        assert_eq!(seen.len(), 1, "nothing was sent after No");
        assert!(seen[0]["body"].get("tapped").is_none());
    }

    #[test]
    fn an_older_box_without_a_reason_is_asked_about_in_general_words() {
        let me = new_me("Marble on Mac");
        let (mut a, seen) = fake_box(None, 2);
        let asked = std::sync::Mutex::new(vec![]);
        block_on(sign_asking(&me, &mut a, &follows_emptied(), |why, phone| {
            asked.lock().unwrap().push((why, phone));
            async { true }
        }))
        .unwrap();
        assert_eq!(*asked.lock().unwrap(), vec![("Your box asks for your Yes before signing this.".to_string(), false)]);
        assert_eq!(seen.join().unwrap()[1]["body"]["tapped"], json!(true));
    }

    /// Level 2 (Keykin SPEC 11.6, The tap): the box keeps it for the phone. This device shows its words and where it is
    /// done, never offers a Yes, and sends nothing more, even if the view answered Yes; no request ever carries `fp`.
    #[test]
    fn level_2_is_shown_and_never_sent_again() {
        for code in ["needs_fingerprint", "no_chip_key"] {
            for answer in [false, true] {
                let me = new_me("Marble on Mac");
                let (mut a, seen) = fake_box_with(Some("Empty your follow list"), 1, Some(code));
                let asked = std::sync::Mutex::new(vec![]);
                let r = block_on(sign_asking(&me, &mut a, &follows_emptied(), |why, phone| {
                    asked.lock().unwrap().push((why, phone));
                    async move { answer }
                }));
                let f = r.err().unwrap();
                assert_eq!(f.code(), code);
                assert!(f.phone_only());
                assert_eq!(f.words(), "Empty your follow list. Do this from your phone.");
                assert_eq!(*asked.lock().unwrap(), vec![("Empty your follow list".to_string(), true)], "shown once, as the phone's");
                let seen = seen.join().unwrap();
                assert_eq!(seen.len(), 1, "nothing sent after it ({code}, view answered {answer})");
                assert!(seen[0].get("fp").is_none(), "this device never sends a fingerprint");
                assert!(seen[0]["body"].get("tapped").is_none());
            }
        }
    }

    /// Whatever this device sends for a level 2 event, it is never something that could sign it: no `fp`, ever, and a
    /// `tapped` it may send for level 1 is not enough for the box.
    #[test]
    fn this_mac_never_sends_what_could_sign_level_2() {
        let me = new_me("Marble on Mac");
        let (mut a, seen) = fake_box_with(Some("Ask relays to erase everything you have ever published"), 1, Some("needs_fingerprint"));
        let r = block_on(sign_event(&me, &mut a, &follows_emptied(), true));
        assert_eq!(r.err().unwrap().code(), "needs_fingerprint", "tapped alone does not sign it");
        let seen = seen.join().unwrap();
        assert!(seen[0].get("fp").is_none());
        assert!(seal_request(json!({ "op": "sign" }), &me, now()).unwrap().get("fp").is_none(), "no request this device makes has one");
        // An account change's needs_fingerprint carries no words: not level 2, and said as before.
        let plain = failure(&json!({ "error": "needs_fingerprint" }), "needs_fingerprint");
        assert!(!plain.phone_only());
        assert_eq!(plain.words(), "Your box said no (needs_fingerprint).");
    }

    #[test]
    fn the_boxs_reason_travels_with_its_error() {
        let f = failure(&json!({ "error": "dated_ahead", "why": "Profile dated 2099-01-01:\na version dated ahead would block every later change" }), "dated_ahead");
        assert_eq!(f.code(), "dated_ahead");
        assert_eq!(f.words(), "Profile dated 2099-01-01: a version dated ahead would block every later change");
        assert!(matches!(failure(&json!({ "error": "blocked", "why": "  " }), "blocked"), Failure::Refused(_)));
        assert_eq!(failure(&json!({ "error": "needs_tap", "why": "x".repeat(400) }), "needs_tap").words().len(), 300);
    }

    #[test]
    fn join_texts() {
        let k = "ab".repeat(32);
        let t = format!(r#"{{"keykin":2,"join":{{"addr":"http://100.64.0.5:7460/","boxKey":"{k}","npub":"{k}"}}}}"#);
        let j = read_join(&t).unwrap();
        assert_eq!(j.addr, "http://100.64.0.5:7460");
        assert!(read_join(r#"{"keykin":2,"invite":{"key":"00"}}"#).is_err());
        assert!(read_join(&t.replace("http://", "ftp://")).is_err());
        let me = new_me("Marble on Mac");
        let inv: Value = serde_json::from_str(&invite(&me)).unwrap();
        assert_eq!(inv["keykin"], json!(2));
        assert_eq!(inv["invite"]["key"], json!(me.key));
    }
}
