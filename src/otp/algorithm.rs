//! Yubico OTP algorithms

use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for Yubico OTP (AES-based one time password) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// Yubico OTP using AES-128
    AES128 = 0x25,

    /// Yubico OTP using AES-192
    AES192 = 0x27,

    /// Yubico OTP using AES-256
    AES256 = 0x28,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `OtpAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x25 => Algorithm::AES128,
            0x27 => Algorithm::AES192,
            0x28 => Algorithm::AES256,
            _ => fail!(TagInvalid, "unknown OTP algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::AES128 => 16,
            Algorithm::AES192 => 24,
            Algorithm::AES256 => 32,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
