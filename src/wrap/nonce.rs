//! Nonces used by the YubiHSM 2's AES-CCM encrypted `wrap::Message`

use ccm::consts::U13;
use rand_core::RngCore;

/// Number of bytes in a nonce used for "wrapping" (i.e AES-CCM encryption)
pub const SIZE: usize = 13;

/// Nonces for AES-CCM keywrapping
#[derive(Debug, Clone)]
pub struct Nonce(pub [u8; SIZE]);

impl Nonce {
    /// Generate a random `wrap::Nonce`
    pub fn generate() -> Self {
        let mut bytes = [0u8; SIZE];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }

    pub(crate) fn to_nonce(&self) -> ccm::Nonce<U13> {
        self.0.into()
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

impl From<&[u8]> for Nonce {
    fn from(bytes: &[u8]) -> Nonce {
        assert_eq!(
            bytes.len(),
            SIZE,
            "nonce must be exactly {} bytes (got {})",
            SIZE,
            bytes.len()
        );
        let mut nonce = [0u8; SIZE];
        nonce.copy_from_slice(bytes);
        Nonce(nonce)
    }
}

impl_array_serializers!(Nonce, SIZE);
