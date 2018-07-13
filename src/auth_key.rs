//! `YubiHSM2` authentication keys (2 * AES-128 symmetric PSK) from which session keys are derived

use clear_on_drop::clear::Clear;
use failure::Error;
#[cfg(feature = "hmac")]
use hmac::Hmac;
#[cfg(feature = "pbkdf2")]
use pbkdf2::pbkdf2;
#[cfg(feature = "sha2")]
use sha2::Sha256;
use std::fmt::{self, Debug};

use object::ObjectId;

/// Auth keys are 2 * AES-128 keys
pub const AUTH_KEY_SIZE: usize = 32;

/// Salt value to use with PBKDF2 when deriving auth keys from a password.
/// This salt is designed to be compatible with the password functionality in
/// yubihsm-shell (otherwise using a static salt is not best practice).
pub const AUTH_KEY_PBKDF2_SALT: &[u8] = b"Yubico";

/// Number of PBKDF2 iterations to perform when deriving auth keys.
/// This number of iterations matches what is performed by yubihsm-shell.
pub const AUTH_KEY_PBKDF2_ITERATIONS: usize = 10_000;

/// Default auth key ID slot
pub const AUTH_KEY_DEFAULT_ID: ObjectId = 1;

/// Password from which default auth key is derived
pub const AUTH_KEY_DEFAULT_PASSWORD: &[u8] = b"password";

/// `YubiHSM2` authentication keys (2 * AES-128 symmetric PSK) from which
/// session keys are derived.c
#[derive(Clone)]
pub struct AuthKey(pub(crate) [u8; AUTH_KEY_SIZE]);

impl AuthKey {
    /// Derive an auth key from a password (using PBKDF2 + static salt).
    /// This method is designed to be compatible with yubihsm-shell. Ensure
    /// you use a long, random password when using this method as the key
    /// derivation algorithm used does little to prevent brute force attacks.
    #[cfg(feature = "passwords")]
    pub fn derive_from_password(password: &[u8]) -> Self {
        let mut kdf_output = [0u8; AUTH_KEY_SIZE];
        pbkdf2::<Hmac<Sha256>>(
            password,
            AUTH_KEY_PBKDF2_SALT,
            AUTH_KEY_PBKDF2_ITERATIONS,
            &mut kdf_output,
        );
        Self::new(kdf_output)
    }

    /// Create an AuthKey from a 32-byte slice, returning an error if the key
    /// is the wrong length
    pub fn from_slice(key_slice: &[u8]) -> Result<Self, Error> {
        ensure!(
            key_slice.len() == AUTH_KEY_SIZE,
            "expected {}-byte key, got {}",
            AUTH_KEY_SIZE,
            key_slice.len()
        );

        let mut key_bytes = [0u8; AUTH_KEY_SIZE];
        key_bytes.copy_from_slice(key_slice);

        Ok(AuthKey(key_bytes))
    }

    /// Create a new AuthKey from the given byte array
    pub fn new(key_bytes: [u8; AUTH_KEY_SIZE]) -> Self {
        AuthKey(key_bytes)
    }

    /// Obtain the encryption key portion of this auth key
    pub(crate) fn enc_key(&self) -> &[u8] {
        &self.0[..16]
    }

    /// Obtain the MAC key portion of this auth key
    pub(crate) fn mac_key(&self) -> &[u8] {
        &self.0[16..]
    }
}

impl Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(f, "yubihsm::AuthKey(...)")
    }
}

/// Derive the default authentication key for all YubiHSM2s
#[cfg(feature = "passwords")]
impl Default for AuthKey {
    fn default() -> Self {
        AuthKey::derive_from_password(AUTH_KEY_DEFAULT_PASSWORD)
    }
}

impl Drop for AuthKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl From<[u8; AUTH_KEY_SIZE]> for AuthKey {
    fn from(key_bytes: [u8; AUTH_KEY_SIZE]) -> AuthKey {
        AuthKey::new(key_bytes)
    }
}

impl_array_serializers!(AuthKey, AUTH_KEY_SIZE);
