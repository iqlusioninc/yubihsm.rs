//! ECDSA algorithms (i.e. hash functions)

use crate::algorithm;

/// Valid algorithms for asymmetric keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// ecdsa-sha1
    SHA1 = 0x17,

    /// ecdsa-sha256
    SHA256 = 0x2b,

    /// ecdsa-sha384
    SHA384 = 0x2c,

    /// ecdsa-sha512
    SHA512 = 0x2d,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `ecdsa::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x17 => Algorithm::SHA1,
            0x2b => Algorithm::SHA256,
            0x2c => Algorithm::SHA384,
            0x2d => Algorithm::SHA512,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown ECDSA algorithm ID: 0x{:02x}",
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
