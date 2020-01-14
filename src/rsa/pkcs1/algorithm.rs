//! RSA PKCS#1v1.5 algorithms

use crate::algorithm;
use anomaly::fail;

/// RSA PKCS#1v1.5: legacy algorithms
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `rsa-pkcs1-sha1`
    Sha1 = 0x01,

    /// `rsa-pkcs1-sha256`
    Sha256 = 0x02,

    /// `rsa-pkcs1-sha384`
    Sha384 = 0x03,

    /// `rsa-pkcs1-sha512`
    Sha512 = 0x04,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x01 => Algorithm::Sha1,
            0x02 => Algorithm::Sha256,
            0x03 => Algorithm::Sha384,
            0x04 => Algorithm::Sha512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown RSASSA-PKCS#1v1.5 algorithm ID: 0x{:02x}",
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
