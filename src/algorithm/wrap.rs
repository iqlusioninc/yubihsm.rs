use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for "wrap" (symmetric encryption/key wrapping) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum WrapAlg {
    /// AES-128 in Counter with CBC-MAC (CCM) mode
    AES128_CCM = 0x1d,

    /// AES-192 in Counter with CBC-MAC (CCM) mode
    AES192_CCM = 0x29,

    /// AES-256 in Counter with CBC-MAC (CCM) mode
    AES256_CCM = 0x2a,
}

impl WrapAlg {
    /// Convert an unsigned byte tag into a `WrapAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x1d => WrapAlg::AES128_CCM,
            0x29 => WrapAlg::AES192_CCM,
            0x2a => WrapAlg::AES256_CCM,
            _ => fail!(TagInvalid, "unknown wrap algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            WrapAlg::AES128_CCM => 16,
            WrapAlg::AES192_CCM => 24,
            WrapAlg::AES256_CCM => 32,
        }
    }
}

impl From<WrapAlg> for Algorithm {
    fn from(alg: WrapAlg) -> Algorithm {
        Algorithm::Wrap(alg)
    }
}

impl_algorithm_serializers!(WrapAlg);
