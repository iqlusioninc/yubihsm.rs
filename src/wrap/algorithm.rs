//! Wrap algorithms

use crate::algorithm;

/// Valid algorithms for "wrap" (symmetric encryption/key wrapping) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// AES-128 in Counter with CBC-MAC (CCM) mode
    AES128_CCM = 0x1d,

    /// AES-192 in Counter with CBC-MAC (CCM) mode
    AES192_CCM = 0x29,

    /// AES-256 in Counter with CBC-MAC (CCM) mode
    AES256_CCM = 0x2a,
}

impl Algorithm {
    /// Convert an unsigned byte tag into a `wrap::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x1d => Algorithm::AES128_CCM,
            0x29 => Algorithm::AES192_CCM,
            0x2a => Algorithm::AES256_CCM,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown wrap algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::AES128_CCM => 16,
            Algorithm::AES192_CCM => 24,
            Algorithm::AES256_CCM => 32,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
