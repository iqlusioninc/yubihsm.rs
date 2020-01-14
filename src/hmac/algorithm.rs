//! HMAC algorithms

use crate::algorithm;
use anomaly::fail;

/// Valid algorithms for HMAC keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `hmac-sha1`
    Sha1 = 0x13,

    /// `hmac-sha256`
    Sha256 = 0x14,

    /// `hmac-sha384`
    Sha384 = 0x15,

    /// `hmac-sha512`
    Sha512 = 0x16,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x13 => Algorithm::Sha1,
            0x14 => Algorithm::Sha256,
            0x15 => Algorithm::Sha384,
            0x16 => Algorithm::Sha512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown HMAC algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Recommended key length (identical to output size)
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::Sha1 => 20,
            Algorithm::Sha256 => 32,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
        }
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn max_key_len(self) -> usize {
        match self {
            Algorithm::Sha1 => 64,
            Algorithm::Sha256 => 64,
            Algorithm::Sha384 => 128,
            Algorithm::Sha512 => 128,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
