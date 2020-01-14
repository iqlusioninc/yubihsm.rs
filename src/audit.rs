//! Auditing options (for use with the `get_option` and `put_option` command)

pub(crate) mod commands;
mod error;

pub use self::error::{Error, ErrorKind};

use crate::command;
use anomaly::fail;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

/// Audit settings for a particular command
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditCommand(pub command::Code, pub AuditOption);

impl AuditCommand {
    /// Get the command type
    pub fn command_type(&self) -> command::Code {
        self.0
    }

    /// Get the audit option
    pub fn audit_option(&self) -> AuditOption {
        self.1
    }
}

/// Auditing policy options
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum AuditOption {
    /// Audit logging disabled
    Off = 0x00,

    /// Audit logging enabled
    On = 0x01,

    /// Audit logging permanently enabled; not possible to turn off
    Fix = 0x02,
}

impl AuditOption {
    /// Convert an unsigned byte into a object::Type (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => AuditOption::Off,
            0x01 => AuditOption::On,
            0x02 => AuditOption::Fix,
            _ => fail!(
                ErrorKind::OptionInvalid,
                "invalid audit option value: {}",
                byte
            ),
        })
    }

    /// Serialize this object type as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for AuditOption {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for AuditOption {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<AuditOption, D::Error> {
        struct AuditOptionVisitor;

        impl<'de> de::Visitor<'de> for AuditOptionVisitor {
            type Value = AuditOption;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned byte with values 0x01, 0x02, or 0x03")
            }

            fn visit_u8<E: de::Error>(self, value: u8) -> Result<AuditOption, E> {
                AuditOption::from_u8(value).or_else(|e| Err(E::custom(e)))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<AuditOption, E> {
                assert!(value < 255);
                AuditOption::from_u8(value as u8).or_else(|e| Err(E::custom(e)))
            }
        }

        deserializer.deserialize_u8(AuditOptionVisitor)
    }
}

/// Tags which identify different types of auditing options
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub(crate) enum AuditTag {
    Force = 0x01,
    Command = 0x03,
}

impl AuditTag {
    /// Convert an unsigned byte into a object::Type (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => AuditTag::Force,
            0x03 => AuditTag::Command,
            _ => fail!(ErrorKind::TagInvalid, "invalid audit tag value: {}", byte),
        })
    }

    /// Serialize this object type as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for AuditTag {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for AuditTag {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<AuditTag, D::Error> {
        struct AuditTagVisitor;

        impl<'de> de::Visitor<'de> for AuditTagVisitor {
            type Value = AuditTag;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned byte with values 0x01 or 0x03")
            }

            fn visit_u8<E: de::Error>(self, value: u8) -> Result<AuditTag, E> {
                AuditTag::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<AuditTag, E> {
                assert!(value < 255);
                AuditTag::from_u8(value as u8).or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(AuditTagVisitor)
    }
}
