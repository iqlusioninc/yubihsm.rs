//! Authentication algorithms

use crate::algorithm;
use anomaly::fail;

/// Valid algorithms for auth keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// YubiHSM AES PSK authentication
    YubicoAes = 0x26,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `authentication::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x26 => Algorithm::YubicoAes,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown auth algorithm ID: 0x{:02x}",
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
            Algorithm::YubicoAes => 32,
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::YubicoAes
    }
}

impl_algorithm_serializers!(Algorithm);
