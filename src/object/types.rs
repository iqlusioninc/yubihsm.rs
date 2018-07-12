use failure::Error;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// Types of objects
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Type {
    /// Raw data
    Opaque = 0x01,

    /// Authentication keys for establishing sessions
    AuthKey = 0x02,

    /// Asymmetric private keys
    AsymmetricKey = 0x03,

    /// Key-wrapping key for exporting/importing keys
    WrapKey = 0x04,

    /// HMAC secret key
    HMACKey = 0x05,

    /// Binary template used to validate SSH certificate requests
    Template = 0x06,

    /// Yubikey-AES OTP encryption/decryption key
    OTPAEADKey = 0x07,
}

impl Type {
    /// Convert an unsigned byte into a ObjectType (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Type::Opaque,
            0x02 => Type::AuthKey,
            0x03 => Type::AsymmetricKey,
            0x04 => Type::WrapKey,
            0x05 => Type::HMACKey,
            0x06 => Type::Template,
            0x07 => Type::OTPAEADKey,
            _ => bail!("invalid object type: {}", byte),
        })
    }

    /// Serialize this object type as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for Type {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Type, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypeVisitor;

        impl<'de> Visitor<'de> for TypeVisitor {
            type Value = Type;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E>(self, value: u8) -> Result<Type, E>
            where
                E: de::Error,
            {
                Type::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(TypeVisitor)
    }
}
