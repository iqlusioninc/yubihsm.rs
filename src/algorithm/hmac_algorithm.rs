use failure::Error;

use super::Algorithm;

/// Valid algorithms for HMAC keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum HMACAlgorithm {
    /// hmac-sha1
    HMAC_SHA1 = Algorithm::HMAC_SHA1 as u8,

    /// hmac-sha256
    HMAC_SHA256 = Algorithm::HMAC_SHA256 as u8,

    /// hmac-sha384
    HMAC_SHA384 = Algorithm::HMAC_SHA384 as u8,

    /// hmac-sha512
    HMAC_SHA512 = Algorithm::HMAC_SHA512 as u8,
}

impl HMACAlgorithm {
    /// Convert from an `Algorithm` into an `HMACAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::HMAC_SHA1 => HMACAlgorithm::HMAC_SHA1,
            Algorithm::HMAC_SHA256 => HMACAlgorithm::HMAC_SHA256,
            Algorithm::HMAC_SHA384 => HMACAlgorithm::HMAC_SHA384,
            Algorithm::HMAC_SHA512 => HMACAlgorithm::HMAC_SHA512,
            _ => bail!("unsupported/bad HMAC algorithm: {:?}", algorithm),
        })
    }

    /// Recommended key length (identical to output size)
    pub fn key_len(self) -> usize {
        match self {
            HMACAlgorithm::HMAC_SHA1 => 20,
            HMACAlgorithm::HMAC_SHA256 => 32,
            HMACAlgorithm::HMAC_SHA384 => 48,
            HMACAlgorithm::HMAC_SHA512 => 64,
        }
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn max_key_len(self) -> usize {
        match self {
            HMACAlgorithm::HMAC_SHA1 => 64,
            HMACAlgorithm::HMAC_SHA256 => 64,
            HMACAlgorithm::HMAC_SHA384 => 128,
            HMACAlgorithm::HMAC_SHA512 => 128,
        }
    }
}

impl_algorithm!(HMACAlgorithm);
