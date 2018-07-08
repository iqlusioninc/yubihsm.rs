use super::Algorithm;

use failure::Error;
use serde::de::Error as DeError;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

/// Valid algorithms for "wrap" (symmetric encryption/key wrapping) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum WrapAlgorithm {
    /// AES-128 in Counter with CBC-MAC (CCM) mode
    AES128_CCM_WRAP = Algorithm::AES128_CCM_WRAP as u8,

    /// AES-192 in Counter with CBC-MAC (CCM) mode
    AES192_CCM_WRAP = Algorithm::AES192_CCM_WRAP as u8,

    /// AES-256 in Counter with CBC-MAC (CCM) mode
    AES256_CCM_WRAP = Algorithm::AES256_CCM_WRAP as u8,
}

impl WrapAlgorithm {
    /// Convert from an `Algorithm` into an `WrapAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::AES128_CCM_WRAP => WrapAlgorithm::AES128_CCM_WRAP,
            Algorithm::AES192_CCM_WRAP => WrapAlgorithm::AES192_CCM_WRAP,
            Algorithm::AES256_CCM_WRAP => WrapAlgorithm::AES256_CCM_WRAP,
            _ => bail!("unsupported/bad wrap algorithm: {:?}", algorithm),
        })
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            WrapAlgorithm::AES128_CCM_WRAP => 16,
            WrapAlgorithm::AES192_CCM_WRAP => 24,
            WrapAlgorithm::AES256_CCM_WRAP => 32,
        }
    }
}

impl_algorithm!(WrapAlgorithm);
