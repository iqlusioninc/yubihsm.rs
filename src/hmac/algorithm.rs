//! HMAC algorithms

use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for HMAC keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// hmac-sha1
    SHA1 = 0x13,

    /// hmac-sha256
    SHA256 = 0x14,

    /// hmac-sha384
    SHA384 = 0x15,

    /// hmac-sha512
    SHA512 = 0x16,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithmorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x13 => Algorithm::SHA1,
            0x14 => Algorithm::SHA256,
            0x15 => Algorithm::SHA384,
            0x16 => Algorithm::SHA512,
            _ => fail!(TagInvalid, "unknown HMAC algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Recommended key length (identical to output size)
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::SHA1 => 20,
            Algorithm::SHA256 => 32,
            Algorithm::SHA384 => 48,
            Algorithm::SHA512 => 64,
        }
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn max_key_len(self) -> usize {
        match self {
            Algorithm::SHA1 => 64,
            Algorithm::SHA256 => 64,
            Algorithm::SHA384 => 128,
            Algorithm::SHA512 => 128,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
