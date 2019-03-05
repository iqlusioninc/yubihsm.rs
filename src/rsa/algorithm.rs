//! RSA-related algorithms

use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// RSA algorithms (signing and encryption)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// rsa-pkcs1-sha1
    PKCS1_SHA1 = 0x01,

    /// rsa-pkcs1-sha256
    PKCS1_SHA256 = 0x02,

    /// rsa-pkcs1-sha384
    PKCS1_SHA384 = 0x03,

    /// rsa-pkcs1-sha512
    PKCS1_SHA512 = 0x04,

    /// rsa-pss-sha1
    PSS_SHA1 = 0x05,

    /// rsa-pss-sha256
    PSS_SHA256 = 0x06,

    /// rsa-pss-sha384
    PSS_SHA384 = 0x07,

    /// rsa-pss-sha512
    PSS_SHA512 = 0x08,

    /// rsa-oaep-sha1
    OAEP_SHA1 = 0x19,

    /// rsa-oaep-sha256
    OAEP_SHA256 = 0x1a,

    /// rsa-oaep-sha384
    OAEP_SHA384 = 0x1b,

    /// rsa-oaep-sha512
    OAEP_SHA512 = 0x1c,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithmorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x01 => Algorithm::PKCS1_SHA1,
            0x02 => Algorithm::PKCS1_SHA256,
            0x03 => Algorithm::PKCS1_SHA384,
            0x04 => Algorithm::PKCS1_SHA512,
            0x05 => Algorithm::PSS_SHA1,
            0x06 => Algorithm::PSS_SHA256,
            0x07 => Algorithm::PSS_SHA384,
            0x08 => Algorithm::PSS_SHA512,
            0x19 => Algorithm::OAEP_SHA1,
            0x1a => Algorithm::OAEP_SHA256,
            0x1b => Algorithm::OAEP_SHA384,
            0x1c => Algorithm::OAEP_SHA512,
            _ => fail!(TagInvalid, "unknown RSA algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl_algorithm_serializers!(Algorithm);
