use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Mask generating functions for RSASSA-PSS
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum MgfAlg {
    /// mgf-sha1
    SHA1 = 0x20,

    /// mgf-sha256
    SHA256 = 0x21,

    /// mgf-sha384
    SHA384 = 0x22,

    /// mgf-sha512
    SHA512 = 0x23,
}

impl MgfAlg {
    /// Convert an unsigned byte tag into an `MgfAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x20 => MgfAlg::SHA1,
            0x21 => MgfAlg::SHA256,
            0x22 => MgfAlg::SHA384,
            0x23 => MgfAlg::SHA512,
            _ => fail!(TagInvalid, "unknown MGF algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<MgfAlg> for Algorithm {
    fn from(alg: MgfAlg) -> Algorithm {
        Algorithm::Mgf(alg)
    }
}

impl_algorithm_serializers!(MgfAlg);
