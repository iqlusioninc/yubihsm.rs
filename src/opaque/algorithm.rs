//! Pseudo-algorithms for opaque data

use crate::algorithm;
use anomaly::fail;

/// Valid algorithms for opaque data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// Arbitrary opaque data
    Data = 0x1e,

    /// X.509 certificates
    X509Certificate = 0x1f,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x1e => Algorithm::Data,
            0x1f => Algorithm::X509Certificate,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown opaque data ID: 0x{:02x}",
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
