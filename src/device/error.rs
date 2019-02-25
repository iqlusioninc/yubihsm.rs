//! Error types which map directly to the YubiHSM2's error codes

use crate::{error::Error, response};

/// Errors which originate in the HSM
pub type DeviceError = Error<DeviceErrorKind>;

/// Kinds of errors which originate in the HSM
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum DeviceErrorKind {
    /// Unknown HSM error codes
    #[fail(display = "unknown HSM error code: 0x{:02x}", code)]
    Unknown {
        /// Unknown error code
        code: u8,
    },

    /// Invalid command
    #[fail(display = "invalid command")]
    InvalidCommand,

    /// Invalid data
    #[fail(display = "invalid data")]
    InvalidData,

    /// Invalid session
    #[fail(display = "invalid session")]
    InvalidSession,

    /// Authentication failure
    #[fail(display = "authentication failed")]
    AuthenticationFailed,

    /// Sessions full (HSM has a max of 16)
    #[fail(display = "sessions full (max 16)")]
    SessionsFull,

    /// Session failed
    #[fail(display = "session failed")]
    SessionFailed,

    /// Storage failed
    #[fail(display = "storage failed")]
    StorageFailed,

    /// Wrong length
    #[fail(display = "incorrect length")]
    WrongLength,

    /// Insufficient permissions
    #[fail(display = "invalid permissions")]
    InsufficientPermissions,

    /// Audit log full
    #[fail(display = "audit log full")]
    LogFull,

    /// Object not found
    #[fail(display = "object not found")]
    ObjectNotFound,

    /// Invalid ID
    #[fail(display = "invalid ID")]
    InvalidId,

    /// Invalid OTP
    #[fail(display = "invalid OTP")]
    InvalidOtp,

    /// Demo mode(?)
    #[fail(display = "demo mode")]
    DemoMode,

    /// Command unexecuted
    #[fail(display = "command unexecuted")]
    CommandUnexecuted,

    /// Generic error
    #[fail(display = "generic error")]
    GenericError,

    /// Object already exists
    #[fail(display = "object already exists")]
    ObjectExists,

    /// SSH CA constraint violation
    #[fail(display = "SSH CA constraint violation")]
    SshCaConstraintViolation,
}

impl DeviceErrorKind {
    /// Create an `DeviceErrorKind` from the given byte tag
    pub fn from_u8(tag: u8) -> DeviceErrorKind {
        match tag {
            0x01 => DeviceErrorKind::InvalidCommand,
            0x02 => DeviceErrorKind::InvalidData,
            0x03 => DeviceErrorKind::InvalidSession,
            0x04 => DeviceErrorKind::AuthenticationFailed,
            0x05 => DeviceErrorKind::SessionsFull,
            0x06 => DeviceErrorKind::SessionFailed,
            0x07 => DeviceErrorKind::StorageFailed,
            0x08 => DeviceErrorKind::WrongLength,
            0x09 => DeviceErrorKind::InsufficientPermissions,
            0x0a => DeviceErrorKind::LogFull,
            0x0b => DeviceErrorKind::ObjectNotFound,
            0x0c => DeviceErrorKind::InvalidId,
            0x0d => DeviceErrorKind::InvalidOtp,
            0x0e => DeviceErrorKind::DemoMode,
            0x0f => DeviceErrorKind::CommandUnexecuted,
            0x10 => DeviceErrorKind::GenericError,
            0x11 => DeviceErrorKind::ObjectExists,
            // TODO: determine correct value for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION
            code => DeviceErrorKind::Unknown { code },
        }
    }

    /// Serialize this `DeviceErrorKind` as a byte tag
    pub fn to_u8(self) -> u8 {
        match self {
            DeviceErrorKind::Unknown { code } => code,
            DeviceErrorKind::InvalidCommand => 0x01,
            DeviceErrorKind::InvalidData => 0x02,
            DeviceErrorKind::InvalidSession => 0x03,
            DeviceErrorKind::AuthenticationFailed => 0x04,
            DeviceErrorKind::SessionsFull => 0x05,
            DeviceErrorKind::SessionFailed => 0x06,
            DeviceErrorKind::StorageFailed => 0x07,
            DeviceErrorKind::WrongLength => 0x08,
            DeviceErrorKind::InsufficientPermissions => 0x09,
            DeviceErrorKind::LogFull => 0x0a,
            DeviceErrorKind::ObjectNotFound => 0x0b,
            DeviceErrorKind::InvalidId => 0x0c,
            DeviceErrorKind::InvalidOtp => 0x0d,
            DeviceErrorKind::DemoMode => 0x0e,
            DeviceErrorKind::CommandUnexecuted => 0x0f,
            DeviceErrorKind::GenericError => 0x10,
            DeviceErrorKind::ObjectExists => 0x11,
            // TODO: determine correct value
            DeviceErrorKind::SshCaConstraintViolation => {
                panic!("don't know device code for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION")
            }
        }
    }

    /// Create an `DeviceError` from the given `response::Code` (if applicable)
    pub fn from_response_code(code: response::Code) -> Option<DeviceErrorKind> {
        Some(match code {
            response::Code::DeviceInvalidCommand => DeviceErrorKind::InvalidCommand,
            response::Code::DeviceInvalidData => DeviceErrorKind::InvalidData,
            response::Code::DeviceInvalidSession => DeviceErrorKind::InvalidSession,
            response::Code::DeviceAuthenticationFailed => DeviceErrorKind::AuthenticationFailed,
            response::Code::DeviceSessionsFull => DeviceErrorKind::SessionsFull,
            response::Code::DeviceSessionFailed => DeviceErrorKind::SessionFailed,
            response::Code::DeviceStorageFailed => DeviceErrorKind::StorageFailed,
            response::Code::DeviceWrongLength => DeviceErrorKind::WrongLength,
            response::Code::DeviceInsufficientPermissions => {
                DeviceErrorKind::InsufficientPermissions
            }
            response::Code::DeviceLogFull => DeviceErrorKind::LogFull,
            response::Code::DeviceObjectNotFound => DeviceErrorKind::ObjectNotFound,
            response::Code::DeviceInvalidId => DeviceErrorKind::InvalidId,
            response::Code::DeviceInvalidOtp => DeviceErrorKind::InvalidOtp,
            response::Code::DeviceDemoMode => DeviceErrorKind::DemoMode,
            response::Code::DeviceCommandUnexecuted => DeviceErrorKind::CommandUnexecuted,
            response::Code::GenericError => DeviceErrorKind::GenericError,
            response::Code::DeviceObjectExists => DeviceErrorKind::ObjectExists,
            response::Code::DeviceSshCaConstraintViolation => {
                DeviceErrorKind::SshCaConstraintViolation
            }
            _ => return None,
        })
    }

    /// Create an `DeviceError` from the given `response::Message` (if applicable)
    pub(crate) fn from_response_message(response: &response::Message) -> Option<DeviceErrorKind> {
        if response.is_err() && response.data.len() == 1 {
            Some(DeviceErrorKind::from_u8(response.data[0]))
        } else {
            None
        }
    }
}
