//! Static Secure Channel keys from which session keys are derived

use clear_on_drop::clear::Clear;
#[cfg(feature = "hmac")]
use hmac::Hmac;
#[cfg(feature = "pbkdf2")]
use pbkdf2::pbkdf2;
#[cfg(feature = "sha2")]
use sha2::Sha256;

use super::KEY_SIZE;

/// Static Secure Channel keys from which session keys are derived
pub struct StaticKeys {
    // Static encryption key (K-ENC)
    pub(crate) enc_key: [u8; KEY_SIZE],

    // Static MAC key (K-MAC)
    pub(crate) mac_key: [u8; KEY_SIZE],
}

impl StaticKeys {
    /// Derive static_keys keys from a password
    #[cfg(feature = "passwords")]
    pub fn derive_from_password(password: &[u8], salt: &[u8], iterations: usize) -> Self {
        let mut kdf_output = [0u8; KEY_SIZE * 2];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut kdf_output);

        let keys = Self::new(&kdf_output);
        kdf_output.clear();

        keys
    }

    /// Create a new keypair from a byte array
    pub fn new(key_bytes: &[u8; KEY_SIZE * 2]) -> Self {
        let mut enc_key = [0u8; KEY_SIZE];
        enc_key.copy_from_slice(&key_bytes[..KEY_SIZE]);

        let mut mac_key = [0u8; KEY_SIZE];
        mac_key.copy_from_slice(&key_bytes[KEY_SIZE..]);

        Self { enc_key, mac_key }
    }
}

impl Drop for StaticKeys {
    fn drop(&mut self) {
        self.enc_key.clear();
        self.mac_key.clear();
    }
}
