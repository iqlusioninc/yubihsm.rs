use failure::Error;

use super::Algorithm;

/// Valid algorithms for auth keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum AuthAlgorithm {
    /// YubiHSM's AES pre-shared key authentication
    YUBICO_AES_AUTH = Algorithm::YUBICO_AES_AUTH as u8,
}

impl AuthAlgorithm {
    /// Convert from an `Algorithm` into an `AuthAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::YUBICO_AES_AUTH => AuthAlgorithm::YUBICO_AES_AUTH,
            _ => bail!("unsupported/bad auth algorithm: {:?}", algorithm),
        })
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            AuthAlgorithm::YUBICO_AES_AUTH => 32,
        }
    }
}

impl_algorithm!(AuthAlgorithm);
