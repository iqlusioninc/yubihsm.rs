//! Cryptographic algorithms supported by the YubiHSM 2

mod error;

pub use self::error::{AlgorithmError, AlgorithmErrorKind};

use crate::{asymmetric, authentication, ecdsa, hmac, kex, opaque, otp, rsa, template, wrap};

/// Cryptographic algorithm types supported by the `YubiHSM 2`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// Asymmetric algorithms
    Asymmetric(asymmetric::Algorithm),

    /// YubiHSM 2 PSK authentication
    Authentication(authentication::Algorithm),

    /// ECDSA algorithms
    Ecdsa(ecdsa::Algorithm),

    /// HMAC algorithms
    Hmac(hmac::Algorithm),

    /// Key exchange algorithms (i.e. Diffie-Hellman)
    Kex(kex::Algorithm),

    /// RSA-PSS mask generating functions
    Mgf(rsa::mgf::Algorithm),

    /// Opaque data types
    Opaque(opaque::Algorithm),

    /// RSA algorithms (signing and encryption)
    Rsa(rsa::Algorithm),

    /// SSH template algorithms
    Template(template::Algorithm),

    /// Object wrap (i.e. HSM-to-HSM encryption) algorithms
    Wrap(wrap::Algorithm),

    /// Yubico OTP algorithms
    YubicoOtp(otp::Algorithm),
}

impl Algorithm {
    /// Convert an unsigned byte into an Algorithm (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, AlgorithmError> {
        Ok(match byte {
            0x01..=0x08 | 0x19..=0x1c => Algorithm::Rsa(rsa::Algorithm::from_u8(byte)?),
            0x09..=0x12 | 0x2e | 0x2f => {
                Algorithm::Asymmetric(asymmetric::Algorithm::from_u8(byte)?)
            }
            0x13..=0x16 => Algorithm::Hmac(hmac::Algorithm::from_u8(byte)?),
            0x17 | 0x2b..=0x2d => Algorithm::Ecdsa(ecdsa::Algorithm::from_u8(byte)?),
            0x18 => Algorithm::Kex(kex::Algorithm::from_u8(byte)?),
            0x1d | 0x29 | 0x2a => Algorithm::Wrap(wrap::Algorithm::from_u8(byte)?),
            0x1e | 0x1f => Algorithm::Opaque(opaque::Algorithm::from_u8(byte)?),
            0x20..=0x23 => Algorithm::Mgf(rsa::mgf::Algorithm::from_u8(byte)?),
            0x24 => Algorithm::Template(template::Algorithm::from_u8(byte)?),
            0x25 | 0x27 | 0x28 => Algorithm::YubicoOtp(otp::Algorithm::from_u8(byte)?),
            0x26 => Algorithm::Authentication(authentication::Algorithm::from_u8(byte)?),
            _ => fail!(
                AlgorithmErrorKind::TagInvalid,
                "unknown algorithm ID: 0x{:02x}",
                byte
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        match self {
            Algorithm::Asymmetric(alg) => alg.to_u8(),
            Algorithm::Authentication(alg) => alg.to_u8(),
            Algorithm::Ecdsa(alg) => alg.to_u8(),
            Algorithm::Hmac(alg) => alg.to_u8(),
            Algorithm::Kex(alg) => alg.to_u8(),
            Algorithm::Mgf(alg) => alg.to_u8(),
            Algorithm::Opaque(alg) => alg.to_u8(),
            Algorithm::YubicoOtp(alg) => alg.to_u8(),
            Algorithm::Rsa(alg) => alg.to_u8(),
            Algorithm::Template(alg) => alg.to_u8(),
            Algorithm::Wrap(alg) => alg.to_u8(),
        }
    }

    /// Get `asymmetric::Algorithm`
    pub fn asymmetric(self) -> Option<asymmetric::Algorithm> {
        match self {
            Algorithm::Asymmetric(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `authentication::Algorithm`
    pub fn authentication(self) -> Option<authentication::Algorithm> {
        match self {
            Algorithm::Authentication(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `ecdsa::Algorithm`
    pub fn ecdsa(self) -> Option<ecdsa::Algorithm> {
        match self {
            Algorithm::Ecdsa(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `hmac::Algorithm`
    pub fn hmac(self) -> Option<hmac::Algorithm> {
        match self {
            Algorithm::Hmac(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `kex::Algorithm`
    pub fn kex(self) -> Option<kex::Algorithm> {
        match self {
            Algorithm::Kex(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `rsa::mgf::Algorithm`
    pub fn mgf(self) -> Option<rsa::mgf::Algorithm> {
        match self {
            Algorithm::Mgf(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `opaque::Algorithm`
    pub fn opaque(self) -> Option<opaque::Algorithm> {
        match self {
            Algorithm::Opaque(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `OtpAlg`
    pub fn otp(self) -> Option<otp::Algorithm> {
        match self {
            Algorithm::YubicoOtp(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `rsa::Algorithm`
    pub fn rsa(self) -> Option<rsa::Algorithm> {
        match self {
            Algorithm::Rsa(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `template::Algorithm`
    pub fn template(self) -> Option<template::Algorithm> {
        match self {
            Algorithm::Template(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `wrap::Algorithm`
    pub fn wrap(self) -> Option<wrap::Algorithm> {
        match self {
            Algorithm::Wrap(alg) => Some(alg),
            _ => None,
        }
    }
}

impl_algorithm_serializers!(Algorithm);

impl From<asymmetric::Algorithm> for Algorithm {
    fn from(alg: asymmetric::Algorithm) -> Algorithm {
        Algorithm::Asymmetric(alg)
    }
}

impl From<authentication::Algorithm> for Algorithm {
    fn from(alg: authentication::Algorithm) -> Algorithm {
        crate::Algorithm::Authentication(alg)
    }
}

impl From<ecdsa::Algorithm> for Algorithm {
    fn from(alg: ecdsa::Algorithm) -> Algorithm {
        Algorithm::Ecdsa(alg)
    }
}

impl From<hmac::Algorithm> for Algorithm {
    fn from(alg: hmac::Algorithm) -> Algorithm {
        Algorithm::Hmac(alg)
    }
}

impl From<kex::Algorithm> for Algorithm {
    fn from(alg: kex::Algorithm) -> Algorithm {
        Algorithm::Kex(alg)
    }
}

impl From<opaque::Algorithm> for Algorithm {
    fn from(alg: opaque::Algorithm) -> Algorithm {
        Algorithm::Opaque(alg)
    }
}

impl From<otp::Algorithm> for Algorithm {
    fn from(alg: otp::Algorithm) -> Algorithm {
        Algorithm::YubicoOtp(alg)
    }
}

impl From<rsa::Algorithm> for Algorithm {
    fn from(alg: rsa::Algorithm) -> Algorithm {
        Algorithm::Rsa(alg)
    }
}

impl From<rsa::mgf::Algorithm> for Algorithm {
    fn from(alg: rsa::mgf::Algorithm) -> Algorithm {
        Algorithm::Mgf(alg)
    }
}

impl From<template::Algorithm> for Algorithm {
    fn from(alg: template::Algorithm) -> Algorithm {
        Algorithm::Template(alg)
    }
}

impl From<wrap::Algorithm> for Algorithm {
    fn from(alg: wrap::Algorithm) -> Algorithm {
        Algorithm::Wrap(alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHM_MAPPING: &[(u8, Algorithm)] = &[
        (0x01, Algorithm::Rsa(rsa::Algorithm::PKCS1_SHA1)),
        (0x02, Algorithm::Rsa(rsa::Algorithm::PKCS1_SHA256)),
        (0x03, Algorithm::Rsa(rsa::Algorithm::PKCS1_SHA384)),
        (0x04, Algorithm::Rsa(rsa::Algorithm::PKCS1_SHA512)),
        (0x05, Algorithm::Rsa(rsa::Algorithm::PSS_SHA1)),
        (0x06, Algorithm::Rsa(rsa::Algorithm::PSS_SHA256)),
        (0x07, Algorithm::Rsa(rsa::Algorithm::PSS_SHA384)),
        (0x08, Algorithm::Rsa(rsa::Algorithm::PSS_SHA512)),
        (0x09, Algorithm::Asymmetric(asymmetric::Algorithm::RSA_2048)),
        (0x0a, Algorithm::Asymmetric(asymmetric::Algorithm::RSA_3072)),
        (0x0b, Algorithm::Asymmetric(asymmetric::Algorithm::RSA_4096)),
        (0x0c, Algorithm::Asymmetric(asymmetric::Algorithm::EC_P256)),
        (0x0d, Algorithm::Asymmetric(asymmetric::Algorithm::EC_P384)),
        (0x0e, Algorithm::Asymmetric(asymmetric::Algorithm::EC_P521)),
        (0x0f, Algorithm::Asymmetric(asymmetric::Algorithm::EC_K256)),
        (0x10, Algorithm::Asymmetric(asymmetric::Algorithm::EC_BP256)),
        (0x11, Algorithm::Asymmetric(asymmetric::Algorithm::EC_BP384)),
        (0x12, Algorithm::Asymmetric(asymmetric::Algorithm::EC_BP512)),
        (0x13, Algorithm::Hmac(hmac::Algorithm::SHA1)),
        (0x14, Algorithm::Hmac(hmac::Algorithm::SHA256)),
        (0x15, Algorithm::Hmac(hmac::Algorithm::SHA384)),
        (0x16, Algorithm::Hmac(hmac::Algorithm::SHA512)),
        (0x17, Algorithm::Ecdsa(ecdsa::Algorithm::SHA1)),
        (0x18, Algorithm::Kex(kex::Algorithm::ECDH)),
        (0x19, Algorithm::Rsa(rsa::Algorithm::OAEP_SHA1)),
        (0x1a, Algorithm::Rsa(rsa::Algorithm::OAEP_SHA256)),
        (0x1b, Algorithm::Rsa(rsa::Algorithm::OAEP_SHA384)),
        (0x1c, Algorithm::Rsa(rsa::Algorithm::OAEP_SHA512)),
        (0x1d, Algorithm::Wrap(wrap::Algorithm::AES128_CCM)),
        (0x1e, Algorithm::Opaque(opaque::Algorithm::DATA)),
        (0x1f, Algorithm::Opaque(opaque::Algorithm::X509_CERTIFICATE)),
        (0x20, Algorithm::Mgf(rsa::mgf::Algorithm::SHA1)),
        (0x21, Algorithm::Mgf(rsa::mgf::Algorithm::SHA256)),
        (0x22, Algorithm::Mgf(rsa::mgf::Algorithm::SHA384)),
        (0x23, Algorithm::Mgf(rsa::mgf::Algorithm::SHA512)),
        (0x24, Algorithm::Template(template::Algorithm::SSH)),
        (0x25, Algorithm::YubicoOtp(otp::Algorithm::AES128)),
        (
            0x26,
            Algorithm::Authentication(authentication::Algorithm::YUBICO_AES),
        ),
        (0x27, Algorithm::YubicoOtp(otp::Algorithm::AES192)),
        (0x28, Algorithm::YubicoOtp(otp::Algorithm::AES256)),
        (0x29, Algorithm::Wrap(wrap::Algorithm::AES192_CCM)),
        (0x2a, Algorithm::Wrap(wrap::Algorithm::AES256_CCM)),
        (0x2b, Algorithm::Ecdsa(ecdsa::Algorithm::SHA256)),
        (0x2c, Algorithm::Ecdsa(ecdsa::Algorithm::SHA384)),
        (0x2d, Algorithm::Ecdsa(ecdsa::Algorithm::SHA512)),
        (0x2e, Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519)),
        (0x2f, Algorithm::Asymmetric(asymmetric::Algorithm::EC_P224)),
    ];

    #[test]
    fn test_from_u8() {
        for (tag, alg) in ALGORITHM_MAPPING {
            assert_eq!(*alg, Algorithm::from_u8(*tag).unwrap());
        }
    }

    #[test]
    fn test_to_u8() {
        for (tag, alg) in ALGORITHM_MAPPING {
            assert_eq!(*tag, alg.to_u8());
        }
    }
}
