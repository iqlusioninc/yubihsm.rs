//! Symmetric algorithm support

use crate::algorithm;

/// Symmetric algorithms
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// AES-128
    Aes128 = 0x32,

    /// AES-192
    Aes192 = 0x33,

    /// AES-256
    Aes256 = 0x34,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x32 => Algorithm::Aes128,
            0x33 => Algorithm::Aes192,
            0x34 => Algorithm::Aes256,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown symmetric algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128 => 16,
            Algorithm::Aes192 => 24,
            Algorithm::Aes256 => 32,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
