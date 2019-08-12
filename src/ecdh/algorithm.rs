//! Key exchange algorithms

use crate::algorithm;

/// Key exchange algorithms (a.k.a. Diffie-Hellman)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// Elliptic Curve Diffie-Hellman
    ECDH = 0x18,
}

impl Algorithm {
    /// Convert an unsigned byte tag into a `kex::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x18 => Algorithm::ECDH,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown key exchange algorithm ID: 0x{:02x}",
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
