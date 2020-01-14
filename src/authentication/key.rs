//! `YubiHSM 2` authentication keys (2 * AES-128 symmetric PSK) from which session keys are derived

use super::{Error, ErrorKind};
use anomaly::ensure;
use getrandom::getrandom;
#[cfg(feature = "hmac")]
use hmac::Hmac;
#[cfg(feature = "pbkdf2")]
use pbkdf2::pbkdf2;
#[cfg(feature = "sha2")]
use sha2::Sha256;
use std::fmt::{self, Debug};
use zeroize::Zeroize;

/// Auth keys are 2 * AES-128 keys
pub const SIZE: usize = 32;

/// Password from which the default auth key is derived
pub const DEFAULT_PASSWORD: &[u8] = b"password";

/// Salt value to use with PBKDF2 when deriving auth keys from a password.
/// This salt is designed to be compatible with the password functionality in
/// yubihsm-shell (otherwise using a static salt is not best practice).
pub const PBKDF2_SALT: &[u8] = b"Yubico";

/// Number of PBKDF2 iterations to perform when deriving auth keys.
/// This number of iterations matches what is performed by yubihsm-shell.
pub const PBKDF2_ITERATIONS: usize = 10_000;

/// `YubiHSM 2` authentication keys (2 * AES-128 symmetric PSK) from which
/// session keys are derived.c
#[derive(Clone)]
pub struct Key(pub(crate) [u8; SIZE]);

impl Key {
    /// Generate a random `Key` using `OsRng`.
    pub fn random() -> Self {
        let mut challenge = [0u8; SIZE];
        getrandom(&mut challenge).expect("RNG failure!");
        Key(challenge)
    }

    /// Derive an auth key from a password (using PBKDF2 + static salt).
    /// This method is designed to be compatible with yubihsm-shell. Ensure
    /// you use a long, random password when using this method as the key
    /// derivation algorithm used does little to prevent brute force attacks.
    #[cfg(feature = "passwords")]
    pub fn derive_from_password(password: &[u8]) -> Self {
        let mut kdf_output = [0u8; SIZE];
        pbkdf2::<Hmac<Sha256>>(password, PBKDF2_SALT, PBKDF2_ITERATIONS, &mut kdf_output);
        Self::new(kdf_output)
    }

    /// Create an `authentication::Key` from a 32-byte slice, returning an
    /// error if the key is the wrong length
    pub fn from_slice(key_slice: &[u8]) -> Result<Self, Error> {
        ensure!(
            key_slice.len() == SIZE,
            ErrorKind::KeySizeInvalid,
            "expected {}-byte key, got {}",
            SIZE,
            key_slice.len()
        );

        let mut key_bytes = [0u8; SIZE];
        key_bytes.copy_from_slice(key_slice);

        Ok(Key(key_bytes))
    }

    /// Create a new Key from the given byte array
    pub fn new(key_bytes: [u8; SIZE]) -> Self {
        Key(key_bytes)
    }

    /// Borrow the secret authentication keys
    pub fn as_secret_slice(&self) -> &[u8] {
        &self.0
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

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(f, "yubihsm::authentication::Key(...)")
    }
}

/// Derive the default authentication key for all YubiHSM 2s
#[cfg(feature = "passwords")]
impl Default for Key {
    fn default() -> Self {
        Key::derive_from_password(DEFAULT_PASSWORD)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<[u8; SIZE]> for Key {
    fn from(key_bytes: [u8; SIZE]) -> Key {
        Key::new(key_bytes)
    }
}

impl_array_serializers!(Key, SIZE);
