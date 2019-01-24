macro_rules! impl_algorithm_serializers {
    ($alg:ident) => {
        impl ::serde::Serialize for $alg {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_u8(self.to_u8())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $alg {
            fn deserialize<D: ::serde::de::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$alg, D::Error> {
                use serde::de::{self, Visitor};
                use std::fmt;

                struct AlgorithmVisitor;

                impl<'de> Visitor<'de> for AlgorithmVisitor {
                    type Value = $alg;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        // TODO: customize this per algorithm
                        formatter.write_str("an unsigned tag byte")
                    }

                    fn visit_u8<E: de::Error>(self, value: u8) -> Result<$alg, E> {
                        $alg::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
                    }
                }

                deserializer.deserialize_u8(AlgorithmVisitor)
            }
        }
    };
}

mod error;
pub use self::error::{AlgorithmError, AlgorithmErrorKind};

mod asymmetric;
mod auth;
mod ecdsa;
mod hmac;
mod kex;
mod mgf;
mod opaque;
mod otp;
mod rsa;
mod template;
mod wrap;

pub use self::{
    asymmetric::AsymmetricAlg, auth::AuthAlg, ecdsa::EcdsaAlg, hmac::HmacAlg, kex::KexAlg,
    mgf::MgfAlg, opaque::OpaqueAlg, otp::OtpAlg, rsa::RsaAlg, template::TemplateAlg, wrap::WrapAlg,
};

/// Cryptographic algorithm types supported by the `YubiHSM2`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// Asymmetric algorithms
    Asymmetric(AsymmetricAlg),

    /// YubiHSM2 PSK authentication
    Auth(AuthAlg),

    /// ECDSA algorithms
    Ecdsa(EcdsaAlg),

    /// HMAC algorithms
    Hmac(HmacAlg),

    /// Key exchange algorithms (i.e. Diffie-Hellman)
    Kex(KexAlg),

    /// RSA-PSS mask generating functions
    Mgf(MgfAlg),

    /// Opaque data types
    Opaque(OpaqueAlg),

    /// Yubico OTP algorithms
    Otp(OtpAlg),

    /// RSA algorithms (signing and encryption)
    Rsa(RsaAlg),

    /// SSH template algorithms
    Template(TemplateAlg),

    /// Object wrap (i.e. HSM-to-HSM encryption) algorithms
    Wrap(WrapAlg),
}

impl Algorithm {
    /// Convert an unsigned byte into an Algorithm (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, AlgorithmError> {
        Ok(match byte {
            0x01..=0x08 | 0x19..=0x1c => Algorithm::Rsa(RsaAlg::from_u8(byte)?),
            0x09..=0x12 | 0x2e | 0x2f => Algorithm::Asymmetric(AsymmetricAlg::from_u8(byte)?),
            0x13..=0x16 => Algorithm::Hmac(HmacAlg::from_u8(byte)?),
            0x17 | 0x2b..=0x2d => Algorithm::Ecdsa(EcdsaAlg::from_u8(byte)?),
            0x18 => Algorithm::Kex(KexAlg::from_u8(byte)?),
            0x1d | 0x29 | 0x2a => Algorithm::Wrap(WrapAlg::from_u8(byte)?),
            0x1e | 0x1f => Algorithm::Opaque(OpaqueAlg::from_u8(byte)?),
            0x20..=0x23 => Algorithm::Mgf(MgfAlg::from_u8(byte)?),
            0x24 => Algorithm::Template(TemplateAlg::from_u8(byte)?),
            0x25 | 0x27 | 0x28 => Algorithm::Otp(OtpAlg::from_u8(byte)?),
            0x26 => Algorithm::Auth(AuthAlg::from_u8(byte)?),
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
            Algorithm::Auth(alg) => alg.to_u8(),
            Algorithm::Ecdsa(alg) => alg.to_u8(),
            Algorithm::Hmac(alg) => alg.to_u8(),
            Algorithm::Kex(alg) => alg.to_u8(),
            Algorithm::Mgf(alg) => alg.to_u8(),
            Algorithm::Opaque(alg) => alg.to_u8(),
            Algorithm::Otp(alg) => alg.to_u8(),
            Algorithm::Rsa(alg) => alg.to_u8(),
            Algorithm::Template(alg) => alg.to_u8(),
            Algorithm::Wrap(alg) => alg.to_u8(),
        }
    }

    /// Get `AsymmetricAlg`
    pub fn asymmetric(self) -> Option<AsymmetricAlg> {
        match self {
            Algorithm::Asymmetric(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `AuthAlg`
    pub fn auth(self) -> Option<AuthAlg> {
        match self {
            Algorithm::Auth(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `EcdsaAlg`
    pub fn ecdsa(self) -> Option<EcdsaAlg> {
        match self {
            Algorithm::Ecdsa(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `HmacAlg`
    pub fn hmac(self) -> Option<HmacAlg> {
        match self {
            Algorithm::Hmac(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `KexAlg`
    pub fn kex(self) -> Option<KexAlg> {
        match self {
            Algorithm::Kex(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `MgfAlg`
    pub fn mgf(self) -> Option<MgfAlg> {
        match self {
            Algorithm::Mgf(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `OpaqueAlg`
    pub fn opaque(self) -> Option<OpaqueAlg> {
        match self {
            Algorithm::Opaque(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `OtpAlg`
    pub fn otp(self) -> Option<OtpAlg> {
        match self {
            Algorithm::Otp(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `RsaAlg`
    pub fn rsa(self) -> Option<RsaAlg> {
        match self {
            Algorithm::Rsa(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `TemplateAlg`
    pub fn template(self) -> Option<TemplateAlg> {
        match self {
            Algorithm::Template(alg) => Some(alg),
            _ => None,
        }
    }

    /// Get `WrapAlg`
    pub fn wrap(self) -> Option<WrapAlg> {
        match self {
            Algorithm::Wrap(alg) => Some(alg),
            _ => None,
        }
    }
}

impl_algorithm_serializers!(Algorithm);

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHM_MAPPING: &[(u8, Algorithm)] = &[
        (0x01, Algorithm::Rsa(RsaAlg::PKCS1_SHA1)),
        (0x02, Algorithm::Rsa(RsaAlg::PKCS1_SHA256)),
        (0x03, Algorithm::Rsa(RsaAlg::PKCS1_SHA384)),
        (0x04, Algorithm::Rsa(RsaAlg::PKCS1_SHA512)),
        (0x05, Algorithm::Rsa(RsaAlg::PSS_SHA1)),
        (0x06, Algorithm::Rsa(RsaAlg::PSS_SHA256)),
        (0x07, Algorithm::Rsa(RsaAlg::PSS_SHA384)),
        (0x08, Algorithm::Rsa(RsaAlg::PSS_SHA512)),
        (0x09, Algorithm::Asymmetric(AsymmetricAlg::RSA_2048)),
        (0x0a, Algorithm::Asymmetric(AsymmetricAlg::RSA_3072)),
        (0x0b, Algorithm::Asymmetric(AsymmetricAlg::RSA_4096)),
        (0x0c, Algorithm::Asymmetric(AsymmetricAlg::EC_P256)),
        (0x0d, Algorithm::Asymmetric(AsymmetricAlg::EC_P384)),
        (0x0e, Algorithm::Asymmetric(AsymmetricAlg::EC_P521)),
        (0x0f, Algorithm::Asymmetric(AsymmetricAlg::EC_K256)),
        (0x10, Algorithm::Asymmetric(AsymmetricAlg::EC_BP256)),
        (0x11, Algorithm::Asymmetric(AsymmetricAlg::EC_BP384)),
        (0x12, Algorithm::Asymmetric(AsymmetricAlg::EC_BP512)),
        (0x13, Algorithm::Hmac(HmacAlg::SHA1)),
        (0x14, Algorithm::Hmac(HmacAlg::SHA256)),
        (0x15, Algorithm::Hmac(HmacAlg::SHA384)),
        (0x16, Algorithm::Hmac(HmacAlg::SHA512)),
        (0x17, Algorithm::Ecdsa(EcdsaAlg::SHA1)),
        (0x18, Algorithm::Kex(KexAlg::ECDH)),
        (0x19, Algorithm::Rsa(RsaAlg::OAEP_SHA1)),
        (0x1a, Algorithm::Rsa(RsaAlg::OAEP_SHA256)),
        (0x1b, Algorithm::Rsa(RsaAlg::OAEP_SHA384)),
        (0x1c, Algorithm::Rsa(RsaAlg::OAEP_SHA512)),
        (0x1d, Algorithm::Wrap(WrapAlg::AES128_CCM)),
        (0x1e, Algorithm::Opaque(OpaqueAlg::DATA)),
        (0x1f, Algorithm::Opaque(OpaqueAlg::X509_CERT)),
        (0x20, Algorithm::Mgf(MgfAlg::SHA1)),
        (0x21, Algorithm::Mgf(MgfAlg::SHA256)),
        (0x22, Algorithm::Mgf(MgfAlg::SHA384)),
        (0x23, Algorithm::Mgf(MgfAlg::SHA512)),
        (0x24, Algorithm::Template(TemplateAlg::SSH)),
        (0x25, Algorithm::Otp(OtpAlg::AES128)),
        (0x26, Algorithm::Auth(AuthAlg::YUBICO_AES)),
        (0x27, Algorithm::Otp(OtpAlg::AES192)),
        (0x28, Algorithm::Otp(OtpAlg::AES256)),
        (0x29, Algorithm::Wrap(WrapAlg::AES192_CCM)),
        (0x2a, Algorithm::Wrap(WrapAlg::AES256_CCM)),
        (0x2b, Algorithm::Ecdsa(EcdsaAlg::SHA256)),
        (0x2c, Algorithm::Ecdsa(EcdsaAlg::SHA384)),
        (0x2d, Algorithm::Ecdsa(EcdsaAlg::SHA512)),
        (0x2e, Algorithm::Asymmetric(AsymmetricAlg::Ed25519)),
        (0x2f, Algorithm::Asymmetric(AsymmetricAlg::EC_P224)),
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
