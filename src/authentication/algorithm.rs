use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for auth keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// YubiHSM AES PSK authentication
    YUBICO_AES = 0x26,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `authentication::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x26 => Algorithm::YUBICO_AES,
            _ => fail!(TagInvalid, "unknown auth algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::YUBICO_AES => 32,
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::YUBICO_AES
    }
}

impl_algorithm_serializers!(Algorithm);
