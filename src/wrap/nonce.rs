//! Nonces used by the YubiHSM 2's AES-CCM encrypted `wrap::Message`

#[cfg(feature = "mockhsm")]
use getrandom::getrandom;

/// Number of bytes in a nonce used for "wrapping" (i.e AES-CCM encryption)
pub const SIZE: usize = 13;

/// Nonces for AES-CCM keywrapping
#[derive(Debug, Clone)]
pub struct Nonce(pub [u8; SIZE]);

impl Nonce {
    /// Generate a random `wrap::Nonce`
    #[cfg(feature = "mockhsm")]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SIZE];
        getrandom(&mut bytes).expect("RNG failure!");
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

impl<'a> From<&'a [u8]> for Nonce {
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
