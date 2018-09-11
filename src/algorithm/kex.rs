use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Key exchange algorithms (a.k.a. Diffie-Hellman)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum KexAlg {
    /// Elliptic Curve Diffie-Hellman
    ECDH = 0x18,
}

impl KexAlg {
    /// Convert an unsigned byte tag into a `KexAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x18 => KexAlg::ECDH,
            _ => fail!(
                TagInvalid,
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

impl From<KexAlg> for Algorithm {
    fn from(alg: KexAlg) -> Algorithm {
        Algorithm::Kex(alg)
    }
}

impl_algorithm_serializers!(KexAlg);
