use failure::Error;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

use commands::CommandType;

/// Codes associated with `YubiHSM2` responses
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResponseCode {
    /// Successful response for the given command type
    Success(CommandType),

    /// HSM memory error (or generic error)
    MemoryError,

    /// Initialization error
    InitError,

    /// Network error
    NetError,

    /// Couldn't find connector
    ConnectorNotFound,

    /// Invalid parameters
    InvalidParams,

    /// Wrong length
    WrongLength,

    /// Buffer is too small
    BufferTooSmall,

    /// Cryptogram mismatches
    CryptogramMismatch,

    /// Session auth error
    AuthSessionError,

    /// MAC mismatch
    MACMismatch,

    /// OK (HSM)
    DeviceOK,

    /// Invalid command (HSM)
    DeviceInvalidCommand,

    /// Invalid data (HSM)
    DeviceInvalidData,

    /// Invalid session (HSM)
    DeviceInvalidSession,

    /// Authentication failure (HSM)
    DeviceAuthFail,

    /// Sessions full (HSM)
    DeviceSessionsFull,

    /// Session failed (HSM)
    DeviceSessionFailed,

    /// Storage failed (HSM)
    DeviceStorageFailed,

    /// Wrong length (HSM)
    DeviceWrongLength,

    /// Invalid permissions (HSM)
    DeviceInvalidPermission,

    /// Audit log full (HSM)
    DeviceLogFull,

    /// Object not found (HSM)
    DeviceObjNotFound,

    /// ID illegal (HSM)
    DeviceIDIllegal,

    /// Invalid OTP (HSM)
    DeviceInvalidOTP,

    /// Demo mode (HSM)
    DeviceDemoMode,

    /// Command unexecuted
    DeviceCmdUnexecuted,

    /// Generic error
    GenericError,

    /// Object already exists
    DeviceObjectExists,

    /// Connector error
    ConnectorError,
}

impl ResponseCode {
    /// Convert an unsigned byte into a ResponseCode (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        let code = i16::from(byte).checked_sub(0x80).unwrap() as i8;

        Ok(match code {
            0...0x7F => ResponseCode::Success(CommandType::from_u8(code as u8)?),
            -1 => ResponseCode::MemoryError,
            -2 => ResponseCode::InitError,
            -3 => ResponseCode::NetError,
            -4 => ResponseCode::ConnectorNotFound,
            -5 => ResponseCode::InvalidParams,
            -6 => ResponseCode::WrongLength,
            -7 => ResponseCode::BufferTooSmall,
            -8 => ResponseCode::CryptogramMismatch,
            -9 => ResponseCode::AuthSessionError,
            -10 => ResponseCode::MACMismatch,
            -11 => ResponseCode::DeviceOK,
            -12 => ResponseCode::DeviceInvalidCommand,
            -13 => ResponseCode::DeviceInvalidData,
            -14 => ResponseCode::DeviceInvalidSession,
            -15 => ResponseCode::DeviceAuthFail,
            -16 => ResponseCode::DeviceSessionsFull,
            -17 => ResponseCode::DeviceSessionFailed,
            -18 => ResponseCode::DeviceStorageFailed,
            -19 => ResponseCode::DeviceWrongLength,
            -20 => ResponseCode::DeviceInvalidPermission,
            -21 => ResponseCode::DeviceLogFull,
            -22 => ResponseCode::DeviceObjNotFound,
            -23 => ResponseCode::DeviceIDIllegal,
            -24 => ResponseCode::DeviceInvalidOTP,
            -25 => ResponseCode::DeviceDemoMode,
            -26 => ResponseCode::DeviceCmdUnexecuted,
            -27 => ResponseCode::GenericError,
            -28 => ResponseCode::DeviceObjectExists,
            -29 => ResponseCode::ConnectorError,
            _ => bail!("invalid response code: {}", code),
        })
    }

    /// Convert a ResponseCode back into its original byte form
    pub fn to_u8(self) -> u8 {
        let code: i8 = match self {
            ResponseCode::Success(cmd_type) => cmd_type as i8,
            ResponseCode::MemoryError => -1,
            ResponseCode::InitError => -2,
            ResponseCode::NetError => -3,
            ResponseCode::ConnectorNotFound => -4,
            ResponseCode::InvalidParams => -5,
            ResponseCode::WrongLength => -6,
            ResponseCode::BufferTooSmall => -7,
            ResponseCode::CryptogramMismatch => -8,
            ResponseCode::AuthSessionError => -9,
            ResponseCode::MACMismatch => -10,
            ResponseCode::DeviceOK => -11,
            ResponseCode::DeviceInvalidCommand => -12,
            ResponseCode::DeviceInvalidData => -13,
            ResponseCode::DeviceInvalidSession => -14,
            ResponseCode::DeviceAuthFail => -15,
            ResponseCode::DeviceSessionsFull => -16,
            ResponseCode::DeviceSessionFailed => -17,
            ResponseCode::DeviceStorageFailed => -18,
            ResponseCode::DeviceWrongLength => -19,
            ResponseCode::DeviceInvalidPermission => -20,
            ResponseCode::DeviceLogFull => -21,
            ResponseCode::DeviceObjNotFound => -22,
            ResponseCode::DeviceIDIllegal => -23,
            ResponseCode::DeviceInvalidOTP => -24,
            ResponseCode::DeviceDemoMode => -25,
            ResponseCode::DeviceCmdUnexecuted => -26,
            ResponseCode::GenericError => -27,
            ResponseCode::DeviceObjectExists => -28,
            ResponseCode::ConnectorError => -29,
        };

        (i16::from(code) + 0x80) as u8
    }

    /// Is this a successful response?
    pub fn is_success(self) -> bool {
        match self {
            ResponseCode::Success(_) => true,
            _ => false,
        }
    }

    /// Is this an error response?
    pub fn is_err(self) -> bool {
        !self.is_success()
    }
}

impl Serialize for ResponseCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for ResponseCode {
    fn deserialize<D>(deserializer: D) -> Result<ResponseCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResponseCodeVisitor;

        impl<'de> Visitor<'de> for ResponseCodeVisitor {
            type Value = ResponseCode;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E>(self, value: u8) -> Result<ResponseCode, E>
            where
                E: de::Error,
            {
                ResponseCode::from_u8(value)
                    .or_else(|_| ResponseCode::from_u8(ResponseCode::DeviceOK.to_u8() - value))
                    .or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(ResponseCodeVisitor)
    }
}
