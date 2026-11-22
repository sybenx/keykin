// The chip that seals this device's secrets: the Secure Enclave on a Mac (src/se.swift). Each use asks for
// the person (Touch ID, or the login password with no sensor). Other systems have none here yet, and
// `keykin` then refuses to join: never a plain file.
//
// Tests: a debug build with KEYKIN_SOFT_CHIP=1 uses a software key kept in the blob instead, so the
// throwaway-box test runs with no finger. A release build has no such code at all.

/// Why the chip gave nothing.
#[derive(Debug)]
pub enum ChipErr {
    /// The person said no, or nobody answered.
    No,
    /// No chip, or it failed.
    Failed(String),
}

/// A chip key: the blob the chip hands back, and its public key (65 bytes, X9.63).
pub struct ChipKey {
    pub blob: Vec<u8>,
    pub public: [u8; 65],
}

#[cfg(debug_assertions)]
fn soft() -> bool {
    std::env::var("KEYKIN_SOFT_CHIP").as_deref() == Ok("1")
}
#[cfg(not(debug_assertions))]
fn soft() -> bool {
    false
}

#[cfg(debug_assertions)]
const SOFT: &[u8] = b"soft-for-tests:";

/// Whether this computer has a chip `keykin` can use.
pub fn available() -> Result<(), String> {
    if soft() {
        return Ok(());
    }
    mac::available()
}

/// A new chip key. Asks for nothing: making one, and sealing to it, need no finger.
pub fn new_key() -> Result<ChipKey, String> {
    #[cfg(debug_assertions)]
    if soft() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public: [u8; 65] = sk.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        return Ok(ChipKey { blob: [SOFT, &sk.to_bytes()[..]].concat(), public });
    }
    mac::new_key()
}

/// The shared x of the chip key and `peer`, after asking the person with `reason`.
pub fn ecdh(blob: &[u8], peer: &[u8; 65], reason: &str) -> Result<[u8; 32], ChipErr> {
    #[cfg(debug_assertions)]
    if let Some(sk) = blob.strip_prefix(SOFT) {
        if !soft() {
            return Err(ChipErr::Failed("a test key, outside a test".into()));
        }
        let sk = p256::SecretKey::from_slice(sk).map_err(|e| ChipErr::Failed(e.to_string()))?;
        let p = p256::PublicKey::from_sec1_bytes(peer).map_err(|e| ChipErr::Failed(e.to_string()))?;
        let s = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), p.as_affine());
        return Ok((*s.raw_secret_bytes()).into());
    }
    mac::ecdh(blob, peer, reason)
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{ChipErr, ChipKey};
    use std::ffi::CString;

    extern "C" {
        fn kk_se_available() -> i32;
        fn kk_se_new(blob: *mut u8, cap: usize, len: *mut usize, public: *mut u8) -> i32;
        fn kk_se_ecdh(blob: *const u8, len: usize, peer: *const u8, reason: *const std::ffi::c_char, out: *mut u8) -> i32;
    }

    pub fn available() -> Result<(), String> {
        match unsafe { kk_se_available() } {
            0 => Ok(()),
            _ => Err("This Mac has no Secure Enclave, so keykin has nowhere safe to keep its piece.".into()),
        }
    }

    pub fn new_key() -> Result<ChipKey, String> {
        available()?;
        let mut blob = vec![0u8; 4096];
        let (mut len, mut public) = (0usize, [0u8; 65]);
        match unsafe { kk_se_new(blob.as_mut_ptr(), blob.len(), &mut len, public.as_mut_ptr()) } {
            0 => {
                blob.truncate(len);
                Ok(ChipKey { blob, public })
            }
            n => Err(format!("The Secure Enclave wouldn’t make a key ({n}).")),
        }
    }

    pub fn ecdh(blob: &[u8], peer: &[u8; 65], reason: &str) -> Result<[u8; 32], ChipErr> {
        let reason = CString::new(reason.replace('\0', " ")).unwrap();
        let mut out = [0u8; 32];
        match unsafe { kk_se_ecdh(blob.as_ptr(), blob.len(), peer.as_ptr(), reason.as_ptr(), out.as_mut_ptr()) } {
            0 => Ok(out),
            1 => Err(ChipErr::No),
            n => Err(ChipErr::Failed(format!("the Secure Enclave failed ({n})"))),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod mac {
    use super::{ChipErr, ChipKey};
    const NOT_YET: &str = "keykin can’t keep a piece safely on this system yet (Linux and Windows come later). It won’t keep one in a plain file.";
    pub fn available() -> Result<(), String> {
        Err(NOT_YET.into())
    }
    pub fn new_key() -> Result<ChipKey, String> {
        Err(NOT_YET.into())
    }
    pub fn ecdh(_: &[u8], _: &[u8; 65], _: &str) -> Result<[u8; 32], ChipErr> {
        Err(ChipErr::Failed(NOT_YET.into()))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    /// The real Secure Enclave, through the Swift part: a key with Touch ID on every use is made with no prompt.
    /// Using it would ask for a finger, so that is left to a person (`keykin sign`). Run: cargo test -- --ignored
    #[test]
    #[ignore]
    fn the_real_chip_makes_a_key_without_asking() {
        super::available().unwrap();
        let k = super::mac::new_key().unwrap();
        assert_eq!(k.public[0], 4);
        assert!(k.blob.len() > 100);
        assert!(p256::PublicKey::from_sec1_bytes(&k.public).is_ok());
    }
}
