use std::fmt;

use failure::Error;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

macro_rules! impl_algorithm {
    ($alg:ident) => {
        impl From<$alg> for Algorithm {
            fn from(algorithm: $alg) -> Algorithm {
                Algorithm::from_u8(algorithm as u8).unwrap()
            }
        }

        impl ::serde::Serialize for $alg {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                Algorithm::from(*self).serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $alg {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$alg, D::Error> {
                use serde::de::Error;
                $alg::from_algorithm(Algorithm::deserialize(deserializer)?)
                    .map_err(|e| D::Error::custom(format!("{}", e)))
            }
        }
    };
}

mod asymmetric_algorithm;
mod auth_algorithm;
mod hmac_algorithm;
mod opaque_algorithm;
mod otp_algorithm;
mod wrap_algorithm;

pub use self::asymmetric_algorithm::AsymmetricAlgorithm;
pub use self::auth_algorithm::AuthAlgorithm;
pub use self::hmac_algorithm::HMACAlgorithm;
pub use self::opaque_algorithm::OpaqueAlgorithm;
pub use self::otp_algorithm::OTPAlgorithm;
pub use self::wrap_algorithm::{WrapAlgorithm, WrapNonce, WrappedData};

/// Cryptographic algorithm types supported by the `YubiHSM2`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Algorithm {
    /// rsa-pkcs1-sha1
    RSA_PKCS1_SHA1 = 0x01,

    /// rsa-pkcs1-sha256
    RSA_PKCS1_SHA256 = 0x02,

    /// rsa-pkcs1-sha384
    RSA_PKCS1_SHA384 = 0x03,

    /// rsa-pkcs1-sha512
    RSA_PKCS1_SHA512 = 0x04,

    /// rsa-pss-sha1
    RSA_PSS_SHA1 = 0x05,

    /// rsa-pss-sha256
    RSA_PSS_SHA256 = 0x06,

    /// rsa-pss-sha384
    RSA_PSS_SHA384 = 0x07,

    /// rsa-pss-sha512
    RSA_PSS_SHA512 = 0x08,

    /// rsa2048
    RSA2048 = 0x09,

    /// rsa3072
    RSA3072 = 0x0a,

    /// rsa4096
    RSA4096 = 0x0b,

    /// ecp256 (secp256r1)
    EC_P256 = 0x0c,

    /// ecp384 (secp384r1)
    EC_P384 = 0x0d,

    /// ecp521 (secp521r1)
    EC_P521 = 0x0e,

    /// eck256 (secp256k1)
    EC_K256 = 0x0f,

    /// ecpb256 (brainpool256r1)
    EC_BP256 = 0x10,

    /// ecpb384 (brainpool384r1)
    EC_BP384 = 0x11,

    /// ecpb512 (brainpool512r1)
    EC_BP512 = 0x12,

    /// hmac-sha1
    HMAC_SHA1 = 0x13,

    /// hmac-sha256
    HMAC_SHA256 = 0x14,

    /// hmac-sha384
    HMAC_SHA384 = 0x15,

    /// hmac-sha512
    HMAC_SHA512 = 0x16,

    /// ecdsa-sha1
    EC_ECDSA_SHA1 = 0x17,

    /// ecdsa
    EC_ECDH = 0x18,

    /// rsa-oaep-sha1
    RSA_OAEP_SHA1 = 0x19,

    /// rsa-oaep-sha256
    RSA_OAEP_SHA256 = 0x1a,

    /// rsa-oaep-sha384
    RSA_OAEP_SHA384 = 0x1b,

    /// rsa-oaep-sha512
    RSA_OAEP_SHA512 = 0x1c,

    /// aes128-ccm-wrap
    AES128_CCM_WRAP = 0x1d,

    /// opaque
    OPAQUE_DATA = 0x1e,

    /// x509-cert
    OPAQUE_X509_CERT = 0x1f,

    /// mgf-sha1
    MGF1_SHA1 = 0x20,

    /// mgf-sha256
    MGF1_SHA256 = 0x21,

    /// mgf-sha384
    MGF1_SHA384 = 0x22,

    /// mgf-sha512
    MGF1_SHA512 = 0x23,

    /// template-ssh
    TEMPL_SSH = 0x24,

    /// yubico-otp-aes128
    YUBICO_OTP_AES128 = 0x25,

    /// yubico-aes-auth
    YUBICO_AES_AUTH = 0x26,

    /// yubico-otp-aes192
    YUBICO_OTP_AES192 = 0x27,

    /// yubico-otp-aes256
    YUBICO_OTP_AES256 = 0x28,

    /// aes192-ccm-wrap
    AES192_CCM_WRAP = 0x29,

    /// aes256-ccm-wrap
    AES256_CCM_WRAP = 0x2a,

    /// ecdsa-sha256
    EC_ECDSA_SHA256 = 0x2b,

    /// ecdsa-sha384
    EC_ECDSA_SHA384 = 0x2c,

    /// ecdsa-sha512
    EC_ECDSA_SHA512 = 0x2d,

    /// ed25519
    EC_ED25519 = 0x2e,

    /// ecp224 (secp224r1)
    EC_P224 = 0x2f,
}

impl Algorithm {
    /// Convert an unsigned byte into an Algorithm (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Algorithm::RSA_PKCS1_SHA1,
            0x02 => Algorithm::RSA_PKCS1_SHA256,
            0x03 => Algorithm::RSA_PKCS1_SHA384,
            0x04 => Algorithm::RSA_PKCS1_SHA512,
            0x05 => Algorithm::RSA_PSS_SHA1,
            0x06 => Algorithm::RSA_PSS_SHA256,
            0x07 => Algorithm::RSA_PSS_SHA384,
            0x08 => Algorithm::RSA_PSS_SHA512,
            0x09 => Algorithm::RSA2048,
            0x0a => Algorithm::RSA3072,
            0x0b => Algorithm::RSA4096,
            0x0c => Algorithm::EC_P256,
            0x0d => Algorithm::EC_P384,
            0x0e => Algorithm::EC_P521,
            0x0f => Algorithm::EC_K256,
            0x10 => Algorithm::EC_BP256,
            0x11 => Algorithm::EC_BP384,
            0x12 => Algorithm::EC_BP512,
            0x13 => Algorithm::HMAC_SHA1,
            0x14 => Algorithm::HMAC_SHA256,
            0x15 => Algorithm::HMAC_SHA384,
            0x16 => Algorithm::HMAC_SHA512,
            0x17 => Algorithm::EC_ECDSA_SHA1,
            0x18 => Algorithm::EC_ECDH,
            0x19 => Algorithm::RSA_OAEP_SHA1,
            0x1a => Algorithm::RSA_OAEP_SHA256,
            0x1b => Algorithm::RSA_OAEP_SHA384,
            0x1c => Algorithm::RSA_OAEP_SHA512,
            0x1d => Algorithm::AES128_CCM_WRAP,
            0x1e => Algorithm::OPAQUE_DATA,
            0x1f => Algorithm::OPAQUE_X509_CERT,
            0x20 => Algorithm::MGF1_SHA1,
            0x21 => Algorithm::MGF1_SHA256,
            0x22 => Algorithm::MGF1_SHA384,
            0x23 => Algorithm::MGF1_SHA512,
            0x24 => Algorithm::TEMPL_SSH,
            0x25 => Algorithm::YUBICO_OTP_AES128,
            0x26 => Algorithm::YUBICO_AES_AUTH,
            0x27 => Algorithm::YUBICO_OTP_AES192,
            0x28 => Algorithm::YUBICO_OTP_AES256,
            0x29 => Algorithm::AES192_CCM_WRAP,
            0x2a => Algorithm::AES256_CCM_WRAP,
            0x2b => Algorithm::EC_ECDSA_SHA256,
            0x2c => Algorithm::EC_ECDSA_SHA384,
            0x2d => Algorithm::EC_ECDSA_SHA512,
            0x2e => Algorithm::EC_ED25519,
            0x2f => Algorithm::EC_P224,
            _ => bail!("invalid algorithm: {:?}", byte),
        })
    }
    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for Algorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Algorithm, D::Error> {
        struct AlgorithmVisitor;

        impl<'de> Visitor<'de> for AlgorithmVisitor {
            type Value = Algorithm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E: de::Error>(self, value: u8) -> Result<Algorithm, E> {
                Algorithm::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(AlgorithmVisitor)
    }
}
