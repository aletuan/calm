//! Where the master key comes from. Production: the macOS Keychain. Tests:
//! a static key.

use crate::{Key, StoreError};

pub trait KeyProvider {
    /// Returns the master key, creating and storing one on first use.
    fn master_key(&self) -> Result<Key, StoreError>;
}

pub struct StaticKey(pub Key);

impl KeyProvider for StaticKey {
    fn master_key(&self) -> Result<Key, StoreError> {
        Ok(self.0.clone())
    }
}

/// Always fails: models a locked or denied Keychain.
pub struct NoKey(pub String);

impl KeyProvider for NoKey {
    fn master_key(&self) -> Result<Key, StoreError> {
        Err(StoreError::KeyUnavailable(self.0.clone()))
    }
}

/// Master key as a generic password item in the login Keychain. Created on
/// first use with 256 random bits; only this signed app can read it without
/// a prompt. Never written to the database or to logs.
#[cfg(target_os = "macos")]
pub struct Keychain {
    pub service: String,
    pub account: String,
}

#[cfg(target_os = "macos")]
impl Keychain {
    pub fn calm() -> Self {
        Keychain {
            service: "com.aletuan.calm.storage".into(),
            account: "master-key-v1".into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl KeyProvider for Keychain {
    fn master_key(&self) -> Result<Key, StoreError> {
        use security_framework::passwords::{get_generic_password, set_generic_password};
        const NOT_FOUND: i32 = -25300; // errSecItemNotFound
        match get_generic_password(&self.service, &self.account) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let arr: [u8; crate::crypto::KEY_LEN] = bytes[..].try_into().map_err(|_| {
                    StoreError::KeyUnavailable("unexpected key format in Keychain".into())
                })?;
                Ok(Key::from_bytes(arr))
            }
            Err(e) if e.code() == NOT_FOUND => {
                let k = Key::random()?;
                set_generic_password(&self.service, &self.account, k.as_bytes())
                    .map_err(|e| StoreError::KeyUnavailable(e.to_string()))?;
                Ok(k)
            }
            Err(e) => Err(StoreError::KeyUnavailable(e.to_string())),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod keychain_tests {
    use super::*;

    /// Touches the real login Keychain, so it is opt-in:
    /// `cargo test -p calm-store -- --ignored keychain`
    #[test]
    #[ignore]
    fn keychain_creates_once_then_returns_the_same_key() {
        let kc = Keychain {
            service: "com.aletuan.calm.storage.test".into(),
            account: format!("test-{}", std::process::id()),
        };
        let a = kc.master_key().expect("create");
        let b = kc.master_key().expect("read back");
        assert_eq!(a.as_bytes(), b.as_bytes());
        security_framework::passwords::delete_generic_password(&kc.service, &kc.account)
            .expect("clean up");
    }
}
