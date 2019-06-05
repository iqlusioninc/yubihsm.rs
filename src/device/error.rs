//! Error types which map directly to the YubiHSM2's error codes

use crate::response;
use failure::Fail;

/// Errors which originate in the HSM
pub type Error = crate::Error<ErrorKind>;

/// Kinds of errors which originate in the HSM
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
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

impl ErrorKind {
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
