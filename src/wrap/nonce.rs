//! Nonces used by the YubiHSM2's AES-CCM encrypted `wrap::Message`

#[cfg(feature = "mockhsm")]
use rand_os::{rand_core::RngCore, OsRng};

/// Number of bytes in a nonce used for "wrapping" (i.e AES-CCM encryption)
pub const SIZE: usize = 13;

/// Nonces for AES-CCM keywrapping
#[derive(Debug, Clone)]
pub struct Nonce(pub [u8; SIZE]);

impl Nonce {
    /// Generate a random `wrap::Nonce`
    #[cfg(feature = "mockhsm")]
    pub fn generate() -> Self {
        let mut rand = OsRng::new().unwrap();
        let mut bytes = [0u8; SIZE];
        rand.fill_bytes(&mut bytes);
        Nonce(bytes)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SIZE]> for Nonce {
    fn from(bytes: [u8; SIZE]) -> Nonce {
        Nonce(bytes)
    }
}

impl_array_serializers!(Nonce, SIZE);
