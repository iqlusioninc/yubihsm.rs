//! Mask generating functions for use with RSASSA-PSS signatures

use crate::algorithm;
use anomaly::fail;

/// Mask generating functions for RSASSA-PSS
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `mgf-sha1`
    Sha1 = 0x20,

    /// `mgf-sha256`
    Sha256 = 0x21,

    /// `mgf-sha384`
    Sha384 = 0x22,

    /// `mgf-sha512`
    Sha512 = 0x23,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x20 => Algorithm::Sha1,
            0x21 => Algorithm::Sha256,
            0x22 => Algorithm::Sha384,
            0x23 => Algorithm::Sha512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown MGF algorithm ID: 0x{:02x}",
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
