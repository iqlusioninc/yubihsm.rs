use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for opaque data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum OpaqueAlg {
    /// Arbitrary opaque data
    DATA = 0x1e,

    /// X.509 certificates
    X509_CERT = 0x1f,
}

impl OpaqueAlg {
    /// Convert an unsigned byte tag into an `OpaqueAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x1e => OpaqueAlg::DATA,
            0x1f => OpaqueAlg::X509_CERT,
            _ => fail!(TagInvalid, "unknown opaque data ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<OpaqueAlg> for Algorithm {
    fn from(alg: OpaqueAlg) -> Algorithm {
        Algorithm::Opaque(alg)
    }
}

impl_algorithm_serializers!(OpaqueAlg);
