use std::ops::{Deref, DerefMut};
use std::{fmt, str};

use failure::Error;
use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};

/// Number of bytes in a label on an object (fixed-size)
pub const LABEL_SIZE: usize = 40;

/// Object identifiers
pub type Id = u16;

/// Sequence identifiers: number of times an object with a given ID has been
/// created in this `YubiHSM` (with all previous versions having been deleted)
pub type SequenceId = u8;

/// Labels attached to objects
pub struct Label(pub [u8; LABEL_SIZE]);

impl Label {
    /// Create a new label from a slice, returning an error if it's over 40-bytes
    pub fn new(label_slice: &[u8]) -> Result<Self, Error> {
        if label_slice.len() > LABEL_SIZE {
            bail!(
                "label too long: {}-bytes (max {})",
                label_slice.len(),
                LABEL_SIZE
            );
        }

        let mut bytes = [0u8; LABEL_SIZE];
        bytes[..label_slice.len()].copy_from_slice(label_slice);
        Ok(Label(bytes))
    }

    /// Create a string representation of this label
    pub fn to_string(&self) -> Result<String, Error> {
        let mut string = str::from_utf8(&self.0)?.to_owned();

        // Ignore trailing zeroes when converting to a String
        if let Some(pos) = string.find('\0') {
            string.truncate(pos);
        }

        Ok(string)
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for Label {
    fn clone(&self) -> Self {
        Self::new(self.as_ref()).unwrap()
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = self
            .to_string()
            .unwrap_or_else(|_| "[INVALID UTF-8 CHARACTER IN LABEL]".to_owned());

        write!(f, "{:?}", string)
    }
}

impl<'a> From<&'a str> for Label {
    fn from(string: &'a str) -> Self {
        Self::new(string.as_bytes()).unwrap()
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Deref for Label {
    type Target = [u8; LABEL_SIZE];

    fn deref(&self) -> &[u8; LABEL_SIZE] {
        &self.0
    }
}

impl DerefMut for Label {
    fn deref_mut(&mut self) -> &mut [u8; LABEL_SIZE] {
        &mut self.0
    }
}

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Label, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelVisitor;

        impl<'de> Visitor<'de> for LabelVisitor {
            type Value = Label;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("40-byte string of arbitrary bytes")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Label, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut label = [0; LABEL_SIZE];

                for elem in label.iter_mut().take(LABEL_SIZE) {
                    match seq.next_element()? {
                        Some(val) => *elem = val,
                        None => return Err(de::Error::custom("end of stream")),
                    };
                }

                Ok(Label(label))
            }
        }

        deserializer.deserialize_seq(LabelVisitor)
    }
}

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

/// Types of objects
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Type {
    /// Raw data
    Opaque = 0x01,

    /// Authentication keys for establishing sessions
    AuthKey = 0x02,

    /// Asymmetric private keys
    Asymmetric = 0x03,

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
            0x03 => Type::Asymmetric,
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
