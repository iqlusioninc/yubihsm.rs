//! ECDSA algorithms (i.e. hash functions)

use super::{NistP256, NistP384, NistP521};
use crate::{algorithm, asymmetric};

#[cfg(feature = "secp256k1")]
use super::Secp256k1;

/// Valid algorithms for asymmetric keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `ecdsa-sha1`
    Sha1 = 0x17,

    /// `ecdsa-sha256`
    Sha256 = 0x2b,

    /// `ecdsa-sha384`
    Sha384 = 0x2c,

    /// `ecdsa-sha512`
    Sha512 = 0x2d,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `ecdsa::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x17 => Algorithm::Sha1,
            0x2b => Algorithm::Sha256,
            0x2c => Algorithm::Sha384,
            0x2d => Algorithm::Sha512,
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

/// Mappings from ECDSA curves to their corresponding asymmetric algorithm
pub trait CurveAlgorithm {
    /// YubiHSM asymmetric algorithm for this elliptic curve
    fn asymmetric_algorithm() -> asymmetric::Algorithm;
}

impl CurveAlgorithm for NistP256 {
    fn asymmetric_algorithm() -> asymmetric::Algorithm {
        asymmetric::Algorithm::EcP256
    }
}

impl CurveAlgorithm for NistP384 {
    fn asymmetric_algorithm() -> asymmetric::Algorithm {
        asymmetric::Algorithm::EcP384
    }
}

impl CurveAlgorithm for NistP521 {
    fn asymmetric_algorithm() -> asymmetric::Algorithm {
        asymmetric::Algorithm::EcP521
    }
}

#[cfg(feature = "secp256k1")]
impl CurveAlgorithm for Secp256k1 {
    fn asymmetric_algorithm() -> asymmetric::Algorithm {
        asymmetric::Algorithm::EcK256
    }
}
