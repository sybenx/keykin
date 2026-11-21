// Where `keykin` keeps this device: one file, `device.json`, in ~/Library/Application Support/Keykin on a
// Mac (KEYKIN_SIGNER_DIR: another folder, for tests). Mode 600, in a 700 folder.
//
// What it says in plain text is public: the account, its box, this device's name, member key (public half)
// and index. What would let anyone sign (the piece's share and the member key's secret) is sealed to the
// chip (chip.rs):
//
//   sealed = eph (65, P-256 X9.63) ‖ nonce (24) ‖ XChaCha20-Poly1305(key, secrets, aad = "keykin-signer-v1:" ‖ member key)
//   key    = HKDF-SHA256(salt "keykin-signer-v1", ECDH(eph, chip key), info eph ‖ chip public)
//
// Sealing uses the chip's public key only, so saving (a catch-up after the keys were cycled) asks for
// nothing. Opening needs the chip, so it asks the person every time.

use std::io::Write;
use std::path::PathBuf;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::chip::{self, ChipErr};
use crate::core::{Account, Me, Piece};

const LABEL: &[u8] = b"keykin-signer-v1";

/// The account as this device knows it, all public.
#[derive(Clone, Serialize, Deserialize)]
pub struct Public {
    pub addr: String,
    pub box_key: String,
    pub npub: String,
    pub c: [String; 2],
    pub i: u32,
    pub epoch: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Chip {
    pub blob: String,
    pub public: String,
}

#[derive(Serialize, Deserialize)]
pub struct File {
    pub v: u8,
    pub name: String,
    /// This device's member key (public half).
    pub key: String,
    pub account: Public,
    pub chip: Chip,
    pub sealed: String,
}

/// What is sealed.
#[derive(Serialize, Deserialize)]
struct Secrets {
    sk: String,
    share: String,
}
impl Drop for Secrets {
    fn drop(&mut self) {
        self.sk.zeroize();
        self.share.zeroize();
    }
}

pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("KEYKIN_SIGNER_DIR") {
        return PathBuf::from(d);
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Keykin")
    } else {
        std::env::var("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|_| home.join(".local/share")).join("keykin")
    }
}
pub fn path() -> PathBuf {
    dir().join("device.json")
}

pub fn load() -> Result<Option<File>, String> {
    match std::fs::read(path()) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!("{} can’t be read: {e}", path().display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Writes the file whole (a new file, then renamed over the old one), mode 600 in a 700 folder.
fn write(f: &File) -> Result<(), String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let d = dir();
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let tmp = d.join(".device.json.new");
    let _ = std::fs::remove_file(&tmp);
    let mut out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    out.write_all(&serde_json::to_vec_pretty(f).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    out.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path()).map_err(|e| e.to_string())
}

pub fn forget() -> Result<bool, String> {
    match std::fs::remove_file(path()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn key_from(shared: &[u8; 32], eph: &[u8], chip_public: &[u8]) -> [u8; 32] {
    let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(LABEL), shared);
    let mut k = [0u8; 32];
    h.expand(&[eph, chip_public].concat(), &mut k).unwrap();
    k
}
fn aad(member: &str) -> Vec<u8> {
    [LABEL, b":", member.as_bytes()].concat()
}

fn seal(s: &Secrets, chip_public: &[u8; 65], member: &str) -> Result<String, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let eph = p256::ecdh::EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let eph_pub = eph.public_key().to_encoded_point(false);
    let chip = p256::PublicKey::from_sec1_bytes(chip_public).map_err(|_| "the chip’s key isn’t a P-256 key")?;
    let mut shared: [u8; 32] = (*eph.diffie_hellman(&chip).raw_secret_bytes()).into();
    let mut key = key_from(&shared, eph_pub.as_bytes(), chip_public);
    shared.zeroize();
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
    let mut msg = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    let ct = chacha20poly1305::XChaCha20Poly1305::new((&key).into()).encrypt((&nonce).into(), Payload { msg: &msg, aad: &aad(member) });
    msg.zeroize();
    key.zeroize();
    Ok(hex::encode([eph_pub.as_bytes(), &nonce, &ct.map_err(|_| "seal failed")?].concat()))
}

/// Why opening failed.
pub enum OpenErr {
    No,
    Failed(String),
}

fn unseal(f: &File, reason: &str) -> Result<Secrets, OpenErr> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let bad = |w: &str| OpenErr::Failed(format!("{}: {w}", path().display()));
    let b = hex::decode(&f.sealed).map_err(|_| bad("the sealed part isn’t hex"))?;
    if b.len() < 65 + 24 + 16 {
        return Err(bad("the sealed part is cut short"));
    }
    let (eph, rest) = b.split_at(65);
    let (nonce, ct) = rest.split_at(24);
    let blob = base64::engine::general_purpose::STANDARD.decode(&f.chip.blob).map_err(|_| bad("the chip key isn’t readable"))?;
    let chip_public = hex::decode(&f.chip.public).map_err(|_| bad("the chip’s public key isn’t hex"))?;
    let mut shared = chip::ecdh(&blob, eph.try_into().unwrap(), reason).map_err(|e| match e {
        ChipErr::No => OpenErr::No,
        ChipErr::Failed(w) => OpenErr::Failed(w),
    })?;
    let mut key = key_from(&shared, eph, &chip_public);
    shared.zeroize();
    let pt = chacha20poly1305::XChaCha20Poly1305::new((&key).into()).decrypt(nonce.into(), Payload { msg: ct, aad: &aad(&f.key) });
    key.zeroize();
    let mut pt = pt.map_err(|_| bad("the sealed part doesn’t open with this Mac’s chip"))?;
    let s = serde_json::from_slice(&pt).map_err(|_| bad("the sealed part isn’t what keykin wrote"));
    pt.zeroize();
    s
}

/// Makes the file for a device that just joined: a new chip key, and the secrets sealed to it.
pub fn create(chip_key: &chip::ChipKey, me: &Me, a: &Account) -> Result<(), String> {
    let s = Secrets { sk: me.sk.clone(), share: a.piece.share.clone() };
    let f = File {
        v: 1,
        name: me.name.clone(),
        key: me.key.clone(),
        account: public_of(a),
        chip: Chip { blob: base64::engine::general_purpose::STANDARD.encode(&chip_key.blob), public: hex::encode(chip_key.public) },
        sealed: seal(&s, &chip_key.public, &me.key)?,
    };
    write(&f)
}

fn public_of(a: &Account) -> Public {
    Public { addr: a.addr.clone(), box_key: a.box_key.clone(), npub: a.npub.clone(), c: a.piece.c.clone(), i: a.piece.i, epoch: a.epoch }
}

/// Opens the secrets (asking the person, with `reason`), as the device and the account the core works with.
pub fn open(f: &File, reason: &str) -> Result<(Me, Account), OpenErr> {
    let s = unseal(f, reason)?;
    let me = Me { sk: s.sk.clone(), key: f.key.clone(), name: f.name.clone() };
    let p = &f.account;
    let a = Account { addr: p.addr.clone(), box_key: p.box_key.clone(), npub: p.npub.clone(), piece: Piece { c: p.c.clone(), i: p.i, share: s.share.clone() }, epoch: p.epoch };
    Ok((me, a))
}

/// Saves the account again after the box moved it to a new epoch: sealed afresh, asking nothing.
pub fn resave(f: &mut File, me: &Me, a: &Account) -> Result<(), String> {
    let public: [u8; 65] = hex::decode(&f.chip.public).ok().and_then(|v| v.try_into().ok()).ok_or("the chip’s public key isn’t readable")?;
    let s = Secrets { sk: me.sk.clone(), share: a.piece.share.clone() };
    f.sealed = seal(&s, &public, &f.key)?;
    f.account = public_of(a);
    write(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_opens_only_with_its_chip_and_its_member_key() {
        // Run with the test chip; the folder is the test's own.
        std::env::set_var("KEYKIN_SOFT_CHIP", "1");
        std::env::set_var("KEYKIN_SIGNER_DIR", std::env::temp_dir().join(format!("kk-signer-unit-{}", std::process::id())));
        let ck = chip::new_key().unwrap();
        let me = crate::core::new_me("Test (Terminal)");
        let a = Account { addr: "http://127.0.0.1:1".into(), box_key: "ab".repeat(32), npub: "cd".repeat(32), piece: Piece { c: ["02".to_string() + &"cd".repeat(32), "03".to_string() + &"ef".repeat(32)], i: 3, share: "11".repeat(32) }, epoch: 4 };
        create(&ck, &me, &a).unwrap();
        let mode = std::fs::metadata(path()).unwrap();
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777, 0o600);
        let text = std::fs::read_to_string(path()).unwrap();
        assert!(!text.contains(&me.sk) && !text.contains(&"11".repeat(32)), "no secret in plain text");

        let mut f = load().unwrap().unwrap();
        let (me2, a2) = open(&f, "test").ok().unwrap();
        assert_eq!(me2.sk, me.sk);
        assert_eq!(a2.piece.share, a.piece.share);
        assert_eq!(a2.epoch, 4);

        // Another member key in the file: the seal no longer opens.
        let k = f.key.clone();
        f.key = "00".repeat(32);
        assert!(matches!(open(&f, "test"), Err(OpenErr::Failed(_))));
        f.key = k;
        // Another chip: no.
        let other = chip::new_key().unwrap();
        let blob = f.chip.blob.clone();
        f.chip.blob = base64::engine::general_purpose::STANDARD.encode(&other.blob);
        assert!(matches!(open(&f, "test"), Err(OpenErr::Failed(_))));
        f.chip.blob = blob;

        // Saved again at a new epoch: sealed afresh, and it still opens.
        let before = f.sealed.clone();
        let mut a3 = a2.clone();
        a3.epoch = 5;
        resave(&mut f, &me2, &a3).unwrap();
        assert_ne!(f.sealed, before);
        let f = load().unwrap().unwrap();
        assert_eq!(f.account.epoch, 5);
        assert_eq!(open(&f, "test").ok().unwrap().1.piece.share, a.piece.share);
        assert!(forget().unwrap());
        assert!(load().unwrap().is_none());
    }
}
