//! Objects stored in the `YubiHSM2`
//!
//! For more information, see:
//! <https://developers.yubico.com/YubiHSM2/Concepts/Object.html>

use byteorder::{BigEndian, ByteOrder};
use failure::Error;

use super::SessionError;

/// Information about an object
#[derive(Debug, Eq, PartialEq)]
pub struct Object {
    /// Object identifiers
    pub id: u16,

    /// Object types
    pub object_type: ObjectType,
}

impl Object {
    pub(crate) fn from_list_response(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 {
            fail!(
                SessionError::ProtocolError,
                "expected 4-byte object entry (got {})",
                bytes.len()
            );
        }

        Ok(Self {
            id: BigEndian::read_u16(&bytes[..2]),
            object_type: ObjectType::from_u8(bytes[2])?,
        })
    }
}

/// Types of objects
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ObjectType {
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

impl ObjectType {
    /// Convert an unsigned byte into a ObjectType (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x01 => ObjectType::Opaque,
            0x02 => ObjectType::AuthKey,
            0x03 => ObjectType::Asymmetric,
            0x04 => ObjectType::WrapKey,
            0x05 => ObjectType::HMACKey,
            0x06 => ObjectType::Template,
            0x07 => ObjectType::OTPAEADKey,
            _ => fail!(SessionError::ProtocolError, "invalid object type: {}", byte),
        })
    }
}
