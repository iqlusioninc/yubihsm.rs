//! Mask generating functions for use with RSASSA-PSS signatures

use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Mask generating functions for RSASSA-PSS
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// mgf-sha1
    SHA1 = 0x20,

    /// mgf-sha256
    SHA256 = 0x21,

    /// mgf-sha384
    SHA384 = 0x22,

    /// mgf-sha512
    SHA512 = 0x23,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithmorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x20 => Algorithm::SHA1,
            0x21 => Algorithm::SHA256,
            0x22 => Algorithm::SHA384,
            0x23 => Algorithm::SHA512,
            _ => fail!(TagInvalid, "unknown MGF algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl_algorithm_serializers!(Algorithm);
