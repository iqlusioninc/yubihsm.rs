//! Response codes

use super::{Error, ErrorKind};
use crate::command;
use anomaly::{fail, format_err};
use serde::{de, ser, Deserialize, Serialize};

/// Codes associated with HSM responses
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Code {
    /// Successful response for the given command type
    Success(command::Code),

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

impl Code {
    /// Convert an unsigned byte into a Code (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        let code = i16::from(byte).checked_sub(0x80).unwrap() as i8;

        Ok(match code {
            0..=0x7F => Code::Success(
                command::Code::from_u8(code as u8)
                    .map_err(|e| format_err!(ErrorKind::CodeInvalid, "{}", e.kind()))?,
            ),
            -1 => Code::MemoryError,
            -2 => Code::InitError,
            -3 => Code::ConnectionError,
            -4 => Code::ConnectorNotFound,
            -5 => Code::InvalidParameters,
            -6 => Code::WrongLength,
            -7 => Code::BufferTooSmall,
            -8 => Code::CryptogramMismatch,
            -9 => Code::SessionAuthenticationFailed,
            -10 => Code::MacMismatch,
            -11 => Code::DeviceOK,
            -12 => Code::DeviceInvalidCommand,
            -13 => Code::DeviceInvalidData,
            -14 => Code::DeviceInvalidSession,
            -15 => Code::DeviceAuthenticationFailed,
            -16 => Code::DeviceSessionsFull,
            -17 => Code::DeviceSessionFailed,
            -18 => Code::DeviceStorageFailed,
            -19 => Code::DeviceWrongLength,
            -20 => Code::DeviceInsufficientPermissions,
            -21 => Code::DeviceLogFull,
            -22 => Code::DeviceObjectNotFound,
            -23 => Code::DeviceInvalidId,
            -24 => Code::DeviceInvalidOtp,
            -25 => Code::DeviceDemoMode,
            -26 => Code::DeviceCommandUnexecuted,
            -27 => Code::GenericError,
            -28 => Code::DeviceObjectExists,
            -29 => Code::ConnectorError,
            -30 => Code::DeviceSshCaConstraintViolation,
            _ => fail!(ErrorKind::CodeInvalid, "invalid response code: {}", code),
        })
    }

    /// Convert a Code back into its original byte form
    pub fn to_u8(self) -> u8 {
        let code: i8 = match self {
            Code::Success(cmd_type) => cmd_type as i8,
            Code::MemoryError => -1,
            Code::InitError => -2,
            Code::ConnectionError => -3,
            Code::ConnectorNotFound => -4,
            Code::InvalidParameters => -5,
            Code::WrongLength => -6,
            Code::BufferTooSmall => -7,
            Code::CryptogramMismatch => -8,
            Code::SessionAuthenticationFailed => -9,
            Code::MacMismatch => -10,
            Code::DeviceOK => -11,
            Code::DeviceInvalidCommand => -12,
            Code::DeviceInvalidData => -13,
            Code::DeviceInvalidSession => -14,
            Code::DeviceAuthenticationFailed => -15,
            Code::DeviceSessionsFull => -16,
            Code::DeviceSessionFailed => -17,
            Code::DeviceStorageFailed => -18,
            Code::DeviceWrongLength => -19,
            Code::DeviceInsufficientPermissions => -20,
            Code::DeviceLogFull => -21,
            Code::DeviceObjectNotFound => -22,
            Code::DeviceInvalidId => -23,
            Code::DeviceInvalidOtp => -24,
            Code::DeviceDemoMode => -25,
            Code::DeviceCommandUnexecuted => -26,
            Code::GenericError => -27,
            Code::DeviceObjectExists => -28,
            Code::ConnectorError => -29,
            Code::DeviceSshCaConstraintViolation => -30,
        };

        (i16::from(code) + 0x80) as u8
    }

    /// Is this a successful response?
    pub fn is_success(self) -> bool {
        match self {
            Code::Success(_) => true,
            _ => false,
        }
    }

    /// Is this an error response?
    pub fn is_err(self) -> bool {
        !self.is_success()
    }
}

impl Serialize for Code {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Code {
    fn deserialize<D>(deserializer: D) -> Result<Code, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;

        use de::Error;
        Code::from_u8(value)
            .or_else(|_| Code::from_u8(Code::DeviceOK.to_u8() - value))
            .map_err(D::Error::custom)
    }
}
