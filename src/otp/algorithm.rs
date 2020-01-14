//! Yubico OTP algorithms

use crate::algorithm;
use anomaly::fail;

/// Valid algorithms for Yubico OTP (AES-based one time password) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// Yubico OTP using AES-128
    Aes128 = 0x25,

    /// Yubico OTP using AES-192
    Aes192 = 0x27,

    /// Yubico OTP using AES-256
    Aes256 = 0x28,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `OtpAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x25 => Algorithm::Aes128,
            0x27 => Algorithm::Aes192,
            0x28 => Algorithm::Aes256,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown OTP algorithm ID: 0x{:02x}",
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
