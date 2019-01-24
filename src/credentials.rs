use crate::auth_key::AuthKey;
use crate::object::ObjectId;

/// Default auth key ID slot
pub const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Credentials used to establish a session with the HSM
pub struct Credentials {
    /// Key ID to authenticate with
    pub auth_key_id: ObjectId,

    /// Auth key to authenticate with
    pub auth_key: AuthKey,
}

impl Credentials {
    /// Create new `Credentials` (auth key ID + `AuthKey`)
    pub fn new(auth_key_id: ObjectId, auth_key: AuthKey) -> Self {
        Self {
            auth_key_id,
            auth_key,
        }
    }

    /// Create a set of credentials from the given auth key and password
    /// Uses the same password-based key derivation method as yubihsm-shell
    /// (PBKDF2 + static salt), which is not particularly strong, so use
    /// of a long, random password is recommended.
    #[cfg(feature = "passwords")]
    pub fn from_password(auth_key_id: ObjectId, password: &[u8]) -> Self {
        Self::new(auth_key_id, AuthKey::derive_from_password(password))
    }
}

#[cfg(feature = "passwords")]
impl Default for Credentials {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_KEY_ID, AuthKey::default())
    }
}
