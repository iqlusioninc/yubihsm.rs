use failure::Error;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// Information about how a key was originally generated
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Object was generated on the device
    Generated = 0x01,

    /// Object was imported from the host
    Imported = 0x02,

    /// Object was generated on a device, keywrapped, and reimported
    WrappedGenerated = 0x11,

    /// Object was imported from host, keywrapped, and reimported
    WrappedImported = 0x12,
}

impl Origin {
    /// Convert an unsigned byte into a ObjectOrigin (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => Origin::Generated,
            0x02 => Origin::Imported,
            0x11 => Origin::WrappedGenerated,
            0x12 => Origin::WrappedImported,
            _ => bail!("invalid object origin: {}", byte),
        })
    }

    /// Serialize this object origin as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for Origin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D>(deserializer: D) -> Result<Origin, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OriginVisitor;

        impl<'de> Visitor<'de> for OriginVisitor {
            type Value = Origin;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E>(self, value: u8) -> Result<Origin, E>
            where
                E: de::Error,
            {
                Origin::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(OriginVisitor)
    }
}
