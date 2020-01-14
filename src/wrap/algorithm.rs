//! Wrap algorithms

use crate::algorithm;
use anomaly::fail;

/// Valid algorithms for "wrap" (symmetric encryption/key wrapping) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// AES-128 in Counter with CBC-MAC (CCM) mode
    Aes128Ccm = 0x1d,

    /// AES-192 in Counter with CBC-MAC (CCM) mode
    Aes192Ccm = 0x29,

    /// AES-256 in Counter with CBC-MAC (CCM) mode
    Aes256Ccm = 0x2a,
}

impl Algorithm {
    /// Convert an unsigned byte tag into a `wrap::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x1d => Algorithm::Aes128Ccm,
            0x29 => Algorithm::Aes192Ccm,
            0x2a => Algorithm::Aes256Ccm,
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
            Algorithm::Aes128Ccm => 16,
            Algorithm::Aes192Ccm => 24,
            Algorithm::Aes256Ccm => 32,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
