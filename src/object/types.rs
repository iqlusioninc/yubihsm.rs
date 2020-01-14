//! Types of objects

use super::{Error, ErrorKind};
use anomaly::fail;
use serde::{de, ser, Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Types of objects
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Type {
    /// Raw data
    Opaque = 0x01,

    /// Authentication keys for establishing sessions
    AuthenticationKey = 0x02,

    /// Asymmetric private keys
    AsymmetricKey = 0x03,

    /// Key-wrapping key for exporting/importing keys
    WrapKey = 0x04,

    /// HMAC secret key
    HmacKey = 0x05,

    /// Binary template used to validate SSH certificate requests
    Template = 0x06,

    /// Yubikey-AES OTP encryption/decryption key
    OtpAeadKey = 0x07,
}

impl Type {
    /// Convert an unsigned byte into a object::Type (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Type::Opaque,
            0x02 => Type::AuthenticationKey,
            0x03 => Type::AsymmetricKey,
            0x04 => Type::WrapKey,
            0x05 => Type::HmacKey,
            0x06 => Type::Template,
            0x07 => Type::OtpAeadKey,
            _ => fail!(ErrorKind::TypeInvalid, "invalid object type: {}", byte),
        })
    }

    /// Serialize this object type as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Type::Opaque => "opaque",
            Type::AuthenticationKey => "authentication-key",
            Type::AsymmetricKey => "asymmetric-key",
            Type::WrapKey => "wrap-key",
            Type::HmacKey => "hmac-key",
            Type::Template => "template",
            Type::OtpAeadKey => "otp-aead-key",
        })
    }
}

impl FromStr for Type {
    type Err = ();

    fn from_str(s: &str) -> Result<Type, ()> {
        Ok(match s {
            "opaque" => Type::Opaque,
            "authentication-key" => Type::AuthenticationKey,
            "asymmetric-key" => Type::AsymmetricKey,
            "wrap-key" => Type::WrapKey,
            "hmac-key" => Type::HmacKey,
            "template" => Type::Template,
            "otp-aead-key" => Type::OtpAeadKey,
            _ => return Err(()),
        })
    }
}

impl Serialize for Type {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Type, D::Error> {
        struct TypeVisitor;

        impl<'de> de::Visitor<'de> for TypeVisitor {
            type Value = Type;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E: de::Error>(self, value: u8) -> Result<Type, E> {
                Type::from_u8(value).map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Type, E> {
                assert!(value < 255);
                Type::from_u8(value as u8).map_err(E::custom)
            }
        }

        deserializer.deserialize_u8(TypeVisitor)
    }
}
