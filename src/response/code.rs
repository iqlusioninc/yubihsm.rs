use failure::Error;
use serde::{
    de::{Deserialize, Deserializer, Error as DeError},
    ser::{Serialize, Serializer},
};

use crate::command::CommandCode;

/// Codes associated with HSM responses
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResponseCode {
    /// Successful response for the given command type
    Success(CommandCode),

    /// HSM memory error (or generic error)
    MemoryError,

    /// Initialization error
    InitError,

    /// Network error
    ConnectionError,

    /// Couldn't find connector
    ConnectorNotFound,

    /// Invalid parameters
    InvalidParameters,

    /// Wrong length
    WrongLength,

    /// Buffer is too small
    BufferTooSmall,

    /// Cryptogram mismatches
    CryptogramMismatch,

    /// Session auth error
    SessionAuthenticationFailed,

    /// MAC mismatch
    MacMismatch,

    /// OK (HSM)
    DeviceOK,

    /// Invalid command (HSM)
    DeviceInvalidCommand,

    /// Invalid data (HSM)
    DeviceInvalidData,

    /// Invalid session (HSM)
    DeviceInvalidSession,

    /// Authentication failure (HSM)
    DeviceAuthenticationFailed,

    /// Sessions full (HSM)
    DeviceSessionsFull,

    /// Session failed (HSM)
    DeviceSessionFailed,

    /// Storage failed (HSM)
    DeviceStorageFailed,

    /// Wrong length (HSM)
    DeviceWrongLength,

    /// Invalid permissions (HSM)
    DeviceInsufficientPermissions,

    /// Audit log full (HSM)
    DeviceLogFull,

    /// Object not found (HSM)
    DeviceObjectNotFound,

    /// Invalid ID (HSM)
    DeviceInvalidId,

    /// Invalid OTP (HSM)
    DeviceInvalidOtp,

    /// Demo mode (HSM)
    DeviceDemoMode,

    /// Command unexecuted
    DeviceCommandUnexecuted,

    /// Generic error
    GenericError,

    /// Object already exists
    DeviceObjectExists,

    /// Connector error
    ConnectorError,

    /// Constraint on CA violated
    DeviceSshCaConstraintViolation,
}

impl ResponseCode {
    /// Convert an unsigned byte into a ResponseCode (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        let code = i16::from(byte).checked_sub(0x80).unwrap() as i8;

        Ok(match code {
            0..=0x7F => ResponseCode::Success(CommandCode::from_u8(code as u8)?),
            -1 => ResponseCode::MemoryError,
            -2 => ResponseCode::InitError,
            -3 => ResponseCode::ConnectionError,
            -4 => ResponseCode::ConnectorNotFound,
            -5 => ResponseCode::InvalidParameters,
            -6 => ResponseCode::WrongLength,
            -7 => ResponseCode::BufferTooSmall,
            -8 => ResponseCode::CryptogramMismatch,
            -9 => ResponseCode::SessionAuthenticationFailed,
            -10 => ResponseCode::MacMismatch,
            -11 => ResponseCode::DeviceOK,
            -12 => ResponseCode::DeviceInvalidCommand,
            -13 => ResponseCode::DeviceInvalidData,
            -14 => ResponseCode::DeviceInvalidSession,
            -15 => ResponseCode::DeviceAuthenticationFailed,
            -16 => ResponseCode::DeviceSessionsFull,
            -17 => ResponseCode::DeviceSessionFailed,
            -18 => ResponseCode::DeviceStorageFailed,
            -19 => ResponseCode::DeviceWrongLength,
            -20 => ResponseCode::DeviceInsufficientPermissions,
            -21 => ResponseCode::DeviceLogFull,
            -22 => ResponseCode::DeviceObjectNotFound,
            -23 => ResponseCode::DeviceInvalidId,
            -24 => ResponseCode::DeviceInvalidOtp,
            -25 => ResponseCode::DeviceDemoMode,
            -26 => ResponseCode::DeviceCommandUnexecuted,
            -27 => ResponseCode::GenericError,
            -28 => ResponseCode::DeviceObjectExists,
            -29 => ResponseCode::ConnectorError,
            -30 => ResponseCode::DeviceSshCaConstraintViolation,
            _ => bail!("invalid response code: {}", code),
        })
    }

    /// Convert a ResponseCode back into its original byte form
    pub fn to_u8(self) -> u8 {
        let code: i8 = match self {
            ResponseCode::Success(cmd_type) => cmd_type as i8,
            ResponseCode::MemoryError => -1,
            ResponseCode::InitError => -2,
            ResponseCode::ConnectionError => -3,
            ResponseCode::ConnectorNotFound => -4,
            ResponseCode::InvalidParameters => -5,
            ResponseCode::WrongLength => -6,
            ResponseCode::BufferTooSmall => -7,
            ResponseCode::CryptogramMismatch => -8,
            ResponseCode::SessionAuthenticationFailed => -9,
            ResponseCode::MacMismatch => -10,
            ResponseCode::DeviceOK => -11,
            ResponseCode::DeviceInvalidCommand => -12,
            ResponseCode::DeviceInvalidData => -13,
            ResponseCode::DeviceInvalidSession => -14,
            ResponseCode::DeviceAuthenticationFailed => -15,
            ResponseCode::DeviceSessionsFull => -16,
            ResponseCode::DeviceSessionFailed => -17,
            ResponseCode::DeviceStorageFailed => -18,
            ResponseCode::DeviceWrongLength => -19,
            ResponseCode::DeviceInsufficientPermissions => -20,
            ResponseCode::DeviceLogFull => -21,
            ResponseCode::DeviceObjectNotFound => -22,
            ResponseCode::DeviceInvalidId => -23,
            ResponseCode::DeviceInvalidOtp => -24,
            ResponseCode::DeviceDemoMode => -25,
            ResponseCode::DeviceCommandUnexecuted => -26,
            ResponseCode::GenericError => -27,
            ResponseCode::DeviceObjectExists => -28,
            ResponseCode::ConnectorError => -29,
            ResponseCode::DeviceSshCaConstraintViolation => -30,
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
        let value = u8::deserialize(deserializer)?;

        ResponseCode::from_u8(value)
            .or_else(|_| ResponseCode::from_u8(ResponseCode::DeviceOK.to_u8() - value))
            .or_else(|e| Err(D::Error::custom(format!("{}", e))))
    }
}
