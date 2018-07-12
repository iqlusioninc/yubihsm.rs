use failure::Error;
#[cfg(feature = "mockhsm")]
use rand::{OsRng, RngCore};
use std::fmt;

use super::Algorithm;

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

pub const WRAP_NONCE_SIZE: usize = 13;

/// Nonces for AES-CCM keywrapping
#[derive(Debug)]
pub struct WrapNonce(pub [u8; WRAP_NONCE_SIZE]);

impl WrapNonce {
    /// Generate a random `WrapNonce`
    #[cfg(feature = "mockhsm")]
    pub fn generate() -> Self {
        let mut rand = OsRng::new().unwrap();
        let mut bytes = [0u8; WRAP_NONCE_SIZE];
        rand.fill_bytes(&mut bytes);
        WrapNonce(bytes)
    }
}

impl AsRef<[u8]> for WrapNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl_array_serializers!(WrapNonce, WRAP_NONCE_SIZE);

/// Data encrypted (i.e. with AES-CCM) under a wrap key
#[derive(Serialize, Deserialize, Debug)]
pub struct WrappedData(pub Vec<u8>);

#[allow(unknown_lints, len_without_is_empty)]
impl WrappedData {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the signature
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for WrappedData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for WrappedData {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
