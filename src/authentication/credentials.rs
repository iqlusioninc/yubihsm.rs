//! Credentials used to authenticate to the HSM (key ID + `authentication::Key`).

use crate::{authentication, object};

/// Default auth key ID slot
pub const DEFAULT_AUTHENTICATION_KEY_ID: object::Id = 1;

/// Credentials used to establish a session with the HSM
#[derive(Clone, Debug)]
pub struct Credentials {
    /// Key ID to authenticate with
    pub authentication_key_id: object::Id,

    /// Auth key to authenticate with
    pub authentication_key: authentication::Key,
}

impl Credentials {
    /// Create new `Credentials` (auth key ID + `authentication::Key`)
    pub fn new(authentication_key_id: object::Id, authentication_key: authentication::Key) -> Self {
        Self {
            authentication_key_id,
            authentication_key,
        }
    }

    /// Create a set of credentials from the given auth key and password
    /// Uses the same password-based key derivation method as yubihsm-shell
    /// (PBKDF2 + static salt), which is not particularly strong, so use
    /// of a long, random password is recommended.
    #[cfg(feature = "passwords")]
    pub fn from_password(authentication_key_id: object::Id, password: &[u8]) -> Self {
        Self::new(
            authentication_key_id,
            authentication::Key::derive_from_password(password),
        )
    }
}

#[cfg(feature = "passwords")]
impl Default for Credentials {
    fn default() -> Self {
        Self::new(
            DEFAULT_AUTHENTICATION_KEY_ID,
            authentication::Key::default(),
        )
    }
}
