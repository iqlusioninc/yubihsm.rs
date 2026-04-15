//! Raw AES algorithms (symmetric key sizes for RSA-AES key wrapping)

use crate::algorithm;

/// Raw AES key size algorithms
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
                "unknown AES algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl_algorithm_serializers!(Algorithm);
