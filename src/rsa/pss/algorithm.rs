//! RSASSA-PSS algorithms

use crate::algorithm;
use anomaly::fail;

/// RSASSA-PSS algorithms
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `rsa-pss-sha1`
    Sha1 = 0x05,

    /// `rsa-pss-sha256`
    Sha256 = 0x06,

    /// `rsa-pss-sha384`
    Sha384 = 0x07,

    /// `rsa-pss-sha512`
    Sha512 = 0x08,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x05 => Algorithm::Sha1,
            0x06 => Algorithm::Sha256,
            0x07 => Algorithm::Sha384,
            0x08 => Algorithm::Sha512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown RSASSA-PSS algorithm ID: 0x{:02x}",
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
