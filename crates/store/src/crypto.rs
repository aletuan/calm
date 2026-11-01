//! AES-256-GCM envelope. Every sealed value is `version(1) || nonce(12) ||
//! ciphertext+tag` and is bound to its row by associated data, so a blob
//! copied into another row or session does not decrypt.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use crate::StoreError;

const NONCE_LEN: usize = 12;

pub const KEY_LEN: usize = 32;
const VERSION: u8 = 1;

/// 256-bit key, wiped from memory on drop.
#[derive(Clone)]
pub struct Key(pub(crate) Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Key(Zeroizing::new(b))
    }

    pub fn random() -> Result<Self, StoreError> {
        let mut b = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(&mut b[..]).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(Key(b))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(…)")
    }
}

fn cipher(key: &Key) -> Aes256Gcm {
    Aes256Gcm::new(key.0.as_ref().into())
}

pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| StoreError::Io(e.to_string()))?;
    let ct = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StoreError::Corrupt("encryption failed".into()))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let bad = || StoreError::Corrupt("authentication failed".into());
    // version + nonce + 16-byte tag at minimum
    if sealed.len() < 1 + NONCE_LEN + 16 || sealed[0] != VERSION {
        return Err(bad());
    }
    let (nonce, ct) = sealed[1..].split_at(NONCE_LEN);
    cipher(key)
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> Key {
        Key::from_bytes([b; KEY_LEN])
    }

    #[test]
    fn round_trip() {
        let s = seal(&k(1), b"aad", b"hello").unwrap();
        assert_eq!(&open(&k(1), b"aad", &s).unwrap()[..], b"hello");
    }

    #[test]
    fn same_plaintext_seals_differently() {
        assert_ne!(
            seal(&k(1), b"a", b"x").unwrap(),
            seal(&k(1), b"a", b"x").unwrap()
        );
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let s = seal(&k(1), b"a", b"SecretNet-SSID").unwrap();
        assert!(!s.windows(6).any(|w| w == b"Secret"));
    }

    #[test]
    fn wrong_key_wrong_aad_and_tampering_fail() {
        let s = seal(&k(1), b"row:1", b"payload").unwrap();
        assert!(open(&k(2), b"row:1", &s).is_err(), "wrong key");
        assert!(open(&k(1), b"row:2", &s).is_err(), "moved to another row");
        for i in 0..s.len() {
            let mut t = s.clone();
            t[i] ^= 0x01;
            assert!(open(&k(1), b"row:1", &t).is_err(), "bit flip at {i}");
        }
        assert!(open(&k(1), b"row:1", &s[..10]).is_err(), "truncated");
        assert!(open(&k(1), b"row:1", &[]).is_err(), "empty");
    }

    #[test]
    fn random_keys_differ() {
        assert_ne!(
            Key::random().unwrap().as_bytes(),
            Key::random().unwrap().as_bytes()
        );
    }
}
