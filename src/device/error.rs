//! Error types which map directly to the YubiHSM2's error codes

use crate::response;
use anomaly::{BoxError, Context};
use thiserror::Error;

/// Errors which originate in the HSM
pub type Error = crate::Error<ErrorKind>;

/// Kinds of errors which originate in the HSM
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Unknown HSM error codes
    #[error("unknown HSM error code: {code:?}")]
    Unknown {
        /// Unknown error code
        code: u8,
    },

    /// Invalid command
    #[error("invalid command")]
    InvalidCommand,

    /// Invalid data
    #[error("invalid data")]
    InvalidData,

    /// Invalid session
    #[error("invalid session")]
    InvalidSession,

    /// Authentication failure
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Sessions full (HSM has a max of 16)
    #[error("sessions full (max 16)")]
    SessionsFull,

    /// Session failed
    #[error("session failed")]
    SessionFailed,

    /// Storage failed
    #[error("storage failed")]
    StorageFailed,

    /// Wrong length
    #[error("wrong length")]
    WrongLength,

    /// Insufficient permissions
    #[error("insufficient permissions")]
    InsufficientPermissions,

    /// Audit log full
    #[error("audit log full")]
    LogFull,

    /// Object not found
    #[error("object not found")]
    ObjectNotFound,

    /// Invalid ID
    #[error("invalid ID")]
    InvalidId,

    /// Invalid OTP
    #[error("invalid OTP")]
    InvalidOtp,

    /// Demo mode(?)
    #[error("demo mode")]
    DemoMode,

    /// Command unexecuted
    #[error("command unexecuted")]
    CommandUnexecuted,

    /// Generic error
    #[error("generic error")]
    GenericError,

    /// Object already exists
    #[error("object already exists")]
    ObjectExists,

    /// SSH CA constraint violation
    #[error("SSH CA constraint violation")]
    SshCaConstraintViolation,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }

    /// Create a `device::ErrorKind` from the given byte tag
    pub fn from_u8(tag: u8) -> ErrorKind {
        match tag {
            0x01 => ErrorKind::InvalidCommand,
            0x02 => ErrorKind::InvalidData,
            0x03 => ErrorKind::InvalidSession,
            0x04 => ErrorKind::AuthenticationFailed,
            0x05 => ErrorKind::SessionsFull,
            0x06 => ErrorKind::SessionFailed,
            0x07 => ErrorKind::StorageFailed,
            0x08 => ErrorKind::WrongLength,
            0x09 => ErrorKind::InsufficientPermissions,
            0x0a => ErrorKind::LogFull,
            0x0b => ErrorKind::ObjectNotFound,
            0x0c => ErrorKind::InvalidId,
            0x0d => ErrorKind::InvalidOtp,
            0x0e => ErrorKind::DemoMode,
            0x0f => ErrorKind::CommandUnexecuted,
            0x10 => ErrorKind::GenericError,
            0x11 => ErrorKind::ObjectExists,
            // TODO: determine correct value for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION
            code => ErrorKind::Unknown { code },
        }
    }

    /// Serialize this `device::ErrorKind` as a byte tag
    pub fn to_u8(self) -> u8 {
        match self {
            ErrorKind::Unknown { code } => code,
            ErrorKind::InvalidCommand => 0x01,
            ErrorKind::InvalidData => 0x02,
            ErrorKind::InvalidSession => 0x03,
            ErrorKind::AuthenticationFailed => 0x04,
            ErrorKind::SessionsFull => 0x05,
            ErrorKind::SessionFailed => 0x06,
            ErrorKind::StorageFailed => 0x07,
            ErrorKind::WrongLength => 0x08,
            ErrorKind::InsufficientPermissions => 0x09,
            ErrorKind::LogFull => 0x0a,
            ErrorKind::ObjectNotFound => 0x0b,
            ErrorKind::InvalidId => 0x0c,
            ErrorKind::InvalidOtp => 0x0d,
            ErrorKind::DemoMode => 0x0e,
            ErrorKind::CommandUnexecuted => 0x0f,
            ErrorKind::GenericError => 0x10,
            ErrorKind::ObjectExists => 0x11,
            // TODO: determine correct value
            ErrorKind::SshCaConstraintViolation => {
                panic!("don't know device code for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION")
            }
        }
    }

    /// Create an `Error` from the given `response::Code` (if applicable)
    pub fn from_response_code(code: response::Code) -> Option<ErrorKind> {
        Some(match code {
            response::Code::DeviceInvalidCommand => ErrorKind::InvalidCommand,
            response::Code::DeviceInvalidData => ErrorKind::InvalidData,
            response::Code::DeviceInvalidSession => ErrorKind::InvalidSession,
            response::Code::DeviceAuthenticationFailed => ErrorKind::AuthenticationFailed,
            response::Code::DeviceSessionsFull => ErrorKind::SessionsFull,
            response::Code::DeviceSessionFailed => ErrorKind::SessionFailed,
            response::Code::DeviceStorageFailed => ErrorKind::StorageFailed,
            response::Code::DeviceWrongLength => ErrorKind::WrongLength,
            response::Code::DeviceInsufficientPermissions => ErrorKind::InsufficientPermissions,
            response::Code::DeviceLogFull => ErrorKind::LogFull,
            response::Code::DeviceObjectNotFound => ErrorKind::ObjectNotFound,
            response::Code::DeviceInvalidId => ErrorKind::InvalidId,
            response::Code::DeviceInvalidOtp => ErrorKind::InvalidOtp,
            response::Code::DeviceDemoMode => ErrorKind::DemoMode,
            response::Code::DeviceCommandUnexecuted => ErrorKind::CommandUnexecuted,
            response::Code::GenericError => ErrorKind::GenericError,
            response::Code::DeviceObjectExists => ErrorKind::ObjectExists,
            response::Code::DeviceSshCaConstraintViolation => ErrorKind::SshCaConstraintViolation,
            _ => return None,
        })
    }

    /// Create an `Error` from the given `response::Message` (if applicable)
    pub(crate) fn from_response_message(response: &response::Message) -> Option<ErrorKind> {
        if response.is_err() && response.data.len() == 1 {
            Some(ErrorKind::from_u8(response.data[0]))
        } else {
            None
        }
    }
}
