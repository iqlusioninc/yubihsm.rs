use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for asymmetric keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum EcdsaAlg {
    /// ecdsa-sha1
    SHA1 = 0x17,

    /// ecdsa-sha256
    SHA256 = 0x2b,

    /// ecdsa-sha384
    SHA384 = 0x2c,

    /// ecdsa-sha512
    SHA512 = 0x2d,
}

impl EcdsaAlg {
    /// Convert an unsigned byte tag into an `EcdsaAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x17 => EcdsaAlg::SHA1,
            0x2b => EcdsaAlg::SHA256,
            0x2c => EcdsaAlg::SHA384,
            0x2d => EcdsaAlg::SHA512,
            _ => fail!(TagInvalid, "unknown ECDSA algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<EcdsaAlg> for Algorithm {
    fn from(alg: EcdsaAlg) -> Algorithm {
        Algorithm::Ecdsa(alg)
    }
}

impl_algorithm_serializers!(EcdsaAlg);
