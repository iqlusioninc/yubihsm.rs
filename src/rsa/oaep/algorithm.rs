//! RSA OAEP algorithms

use crate::algorithm;
use anomaly::fail;

/// RSA Optimal Asymmetric Encryption Padding (OAEP) algorithms
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `rsa-oaep-sha1`
    Sha1 = 0x19,

    /// `rsa-oaep-sha256`
    Sha256 = 0x1a,

    /// `rsa-oaep-sha384`
    Sha384 = 0x1b,

    /// `rsa-oaep-sha512`
    Sha512 = 0x1c,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x19 => Algorithm::Sha1,
            0x1a => Algorithm::Sha256,
            0x1b => Algorithm::Sha384,
            0x1c => Algorithm::Sha512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown RSA OAEP algorithm ID: 0x{:02x}",
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
