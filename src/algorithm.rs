//! Cryptographic algorithms supported by the YubiHSM 2

mod error;

pub use self::error::{Error, ErrorKind};

use crate::{asymmetric, authentication, ecdh, ecdsa, hmac, opaque, otp, rsa, template, wrap};
use anomaly::fail;

/// Cryptographic algorithm types supported by the `YubiHSM 2`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// Asymmetric algorithms
    Asymmetric(asymmetric::Algorithm),

    /// YubiHSM 2 symmetric PSK authentication
    Authentication(authentication::Algorithm),

    /// Elliptic Curve Diffie-Hellman (i.e. key exchange) algorithms
    Ecdh(ecdh::Algorithm),

    /// ECDSA algorithms
    Ecdsa(ecdsa::Algorithm),

    /// HMAC algorithms
    Hmac(hmac::Algorithm),

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
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01..=0x08 | 0x19..=0x1c => Algorithm::Rsa(rsa::Algorithm::from_u8(byte)?),
            0x09..=0x12 | 0x2e | 0x2f => {
                Algorithm::Asymmetric(asymmetric::Algorithm::from_u8(byte)?)
            }
            0x13..=0x16 => Algorithm::Hmac(hmac::Algorithm::from_u8(byte)?),
            0x17 | 0x2b..=0x2d => Algorithm::Ecdsa(ecdsa::Algorithm::from_u8(byte)?),
            0x18 => Algorithm::Ecdh(ecdh::Algorithm::from_u8(byte)?),
            0x1d | 0x29 | 0x2a => Algorithm::Wrap(wrap::Algorithm::from_u8(byte)?),
            0x1e | 0x1f => Algorithm::Opaque(opaque::Algorithm::from_u8(byte)?),
            0x20..=0x23 => Algorithm::Mgf(rsa::mgf::Algorithm::from_u8(byte)?),
            0x24 => Algorithm::Template(template::Algorithm::from_u8(byte)?),
            0x25 | 0x27 | 0x28 => Algorithm::YubicoOtp(otp::Algorithm::from_u8(byte)?),
            0x26 => Algorithm::Authentication(authentication::Algorithm::from_u8(byte)?),
            _ => fail!(
                ErrorKind::TagInvalid,
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
            Algorithm::Ecdh(alg) => alg.to_u8(),
            Algorithm::Ecdsa(alg) => alg.to_u8(),
            Algorithm::Hmac(alg) => alg.to_u8(),
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

    /// Get `ecdh::Algorithm`
    pub fn ecdh(self) -> Option<ecdh::Algorithm> {
        match self {
            Algorithm::Ecdh(alg) => Some(alg),
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

impl From<ecdh::Algorithm> for Algorithm {
    fn from(alg: ecdh::Algorithm) -> Algorithm {
        Algorithm::Ecdh(alg)
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
        (
            0x01,
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha1)),
        ),
        (
            0x02,
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha256)),
        ),
        (
            0x03,
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha384)),
        ),
        (
            0x04,
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha512)),
        ),
        (
            0x05,
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha1)),
        ),
        (
            0x06,
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha256)),
        ),
        (
            0x07,
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha384)),
        ),
        (
            0x08,
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha512)),
        ),
        (0x09, Algorithm::Asymmetric(asymmetric::Algorithm::Rsa2048)),
        (0x0a, Algorithm::Asymmetric(asymmetric::Algorithm::Rsa3072)),
        (0x0b, Algorithm::Asymmetric(asymmetric::Algorithm::Rsa4096)),
        (0x0c, Algorithm::Asymmetric(asymmetric::Algorithm::EcP256)),
        (0x0d, Algorithm::Asymmetric(asymmetric::Algorithm::EcP384)),
        (0x0e, Algorithm::Asymmetric(asymmetric::Algorithm::EcP521)),
        (0x0f, Algorithm::Asymmetric(asymmetric::Algorithm::EcK256)),
        (0x10, Algorithm::Asymmetric(asymmetric::Algorithm::EcBp256)),
        (0x11, Algorithm::Asymmetric(asymmetric::Algorithm::EcBp384)),
        (0x12, Algorithm::Asymmetric(asymmetric::Algorithm::EcBp512)),
        (0x13, Algorithm::Hmac(hmac::Algorithm::Sha1)),
        (0x14, Algorithm::Hmac(hmac::Algorithm::Sha256)),
        (0x15, Algorithm::Hmac(hmac::Algorithm::Sha384)),
        (0x16, Algorithm::Hmac(hmac::Algorithm::Sha512)),
        (0x17, Algorithm::Ecdsa(ecdsa::Algorithm::Sha1)),
        (0x18, Algorithm::Ecdh(ecdh::Algorithm::Ecdh)),
        (
            0x19,
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha1)),
        ),
        (
            0x1a,
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha256)),
        ),
        (
            0x1b,
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha384)),
        ),
        (
            0x1c,
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha512)),
        ),
        (0x1d, Algorithm::Wrap(wrap::Algorithm::Aes128Ccm)),
        (0x1e, Algorithm::Opaque(opaque::Algorithm::Data)),
        (0x1f, Algorithm::Opaque(opaque::Algorithm::X509Certificate)),
        (0x20, Algorithm::Mgf(rsa::mgf::Algorithm::Sha1)),
        (0x21, Algorithm::Mgf(rsa::mgf::Algorithm::Sha256)),
        (0x22, Algorithm::Mgf(rsa::mgf::Algorithm::Sha384)),
        (0x23, Algorithm::Mgf(rsa::mgf::Algorithm::Sha512)),
        (0x24, Algorithm::Template(template::Algorithm::Ssh)),
        (0x25, Algorithm::YubicoOtp(otp::Algorithm::Aes128)),
        (
            0x26,
            Algorithm::Authentication(authentication::Algorithm::YubicoAes),
        ),
        (0x27, Algorithm::YubicoOtp(otp::Algorithm::Aes192)),
        (0x28, Algorithm::YubicoOtp(otp::Algorithm::Aes256)),
        (0x29, Algorithm::Wrap(wrap::Algorithm::Aes192Ccm)),
        (0x2a, Algorithm::Wrap(wrap::Algorithm::Aes256Ccm)),
        (0x2b, Algorithm::Ecdsa(ecdsa::Algorithm::Sha256)),
        (0x2c, Algorithm::Ecdsa(ecdsa::Algorithm::Sha384)),
        (0x2d, Algorithm::Ecdsa(ecdsa::Algorithm::Sha512)),
        (0x2e, Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519)),
        (0x2f, Algorithm::Asymmetric(asymmetric::Algorithm::EcP224)),
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
