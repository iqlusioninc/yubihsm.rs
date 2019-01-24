pub use failure::{Backtrace, Context, Fail};
use std::error::Error as StdError;
use std::fmt::{self, Display};

use crate::response::{ResponseCode, ResponseMessage};

/// Placeholder for when we have no description for an error
const NO_DESCRIPTION: &str = "(no description)";

/// Error types used by this library
#[derive(Debug)]
pub struct Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    inner: Context<T>,
    description: Option<String>,
}

impl<T> Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    /// Create a new error type from its kind
    pub fn new(kind: T, description: Option<String>) -> Self {
        Self {
            inner: Context::new(kind),
            description,
        }
    }

    /// Obtain the error's `Kind`
    pub fn kind(&self) -> T {
        *self.inner.get_context()
    }
}

impl<T> Display for Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.description {
            None => Display::fmt(&self.inner, f),
            Some(ref desc) => {
                if desc == NO_DESCRIPTION {
                    Display::fmt(&self.inner, f)
                } else {
                    write!(f, "{}: {}", &self.inner, desc)
                }
            }
        }
    }
}

impl<T> StdError for Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    /// Obtain the error's description
    fn description(&self) -> &str {
        match self.description {
            Some(ref s) => s,
            None => NO_DESCRIPTION,
        }
    }
}

/// Errors which originate in the HSM
pub type HsmError = Error<HsmErrorKind>;

/// Kinds of errors which originate in the HSM
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum HsmErrorKind {
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

impl HsmErrorKind {
    /// Create an `HsmErrorKind` from the given byte tag
    pub fn from_u8(tag: u8) -> HsmErrorKind {
        match tag {
            0x01 => HsmErrorKind::InvalidCommand,
            0x02 => HsmErrorKind::InvalidData,
            0x03 => HsmErrorKind::InvalidSession,
            0x04 => HsmErrorKind::AuthenticationFailed,
            0x05 => HsmErrorKind::SessionsFull,
            0x06 => HsmErrorKind::SessionFailed,
            0x07 => HsmErrorKind::StorageFailed,
            0x08 => HsmErrorKind::WrongLength,
            0x09 => HsmErrorKind::InsufficientPermissions,
            0x0a => HsmErrorKind::LogFull,
            0x0b => HsmErrorKind::ObjectNotFound,
            0x0c => HsmErrorKind::InvalidId,
            0x0d => HsmErrorKind::InvalidOtp,
            0x0e => HsmErrorKind::DemoMode,
            0x0f => HsmErrorKind::CommandUnexecuted,
            0x10 => HsmErrorKind::GenericError,
            0x11 => HsmErrorKind::ObjectExists,
            // TODO: determine correct value for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION
            code => HsmErrorKind::Unknown { code },
        }
    }

    /// Serialize this `HsmErrorKind` as a byte tag
    pub fn to_u8(self) -> u8 {
        match self {
            HsmErrorKind::Unknown { code } => code,
            HsmErrorKind::InvalidCommand => 0x01,
            HsmErrorKind::InvalidData => 0x02,
            HsmErrorKind::InvalidSession => 0x03,
            HsmErrorKind::AuthenticationFailed => 0x04,
            HsmErrorKind::SessionsFull => 0x05,
            HsmErrorKind::SessionFailed => 0x06,
            HsmErrorKind::StorageFailed => 0x07,
            HsmErrorKind::WrongLength => 0x08,
            HsmErrorKind::InsufficientPermissions => 0x09,
            HsmErrorKind::LogFull => 0x0a,
            HsmErrorKind::ObjectNotFound => 0x0b,
            HsmErrorKind::InvalidId => 0x0c,
            HsmErrorKind::InvalidOtp => 0x0d,
            HsmErrorKind::DemoMode => 0x0e,
            HsmErrorKind::CommandUnexecuted => 0x0f,
            HsmErrorKind::GenericError => 0x10,
            HsmErrorKind::ObjectExists => 0x11,
            // TODO: determine correct value
            HsmErrorKind::SshCaConstraintViolation => {
                panic!("don't know device code for YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION")
            }
        }
    }

    /// Create an `HsmError` from the given `ResponseCode` (if applicable)
    pub fn from_response_code(code: ResponseCode) -> Option<HsmErrorKind> {
        Some(match code {
            ResponseCode::DeviceInvalidCommand => HsmErrorKind::InvalidCommand,
            ResponseCode::DeviceInvalidData => HsmErrorKind::InvalidData,
            ResponseCode::DeviceInvalidSession => HsmErrorKind::InvalidSession,
            ResponseCode::DeviceAuthenticationFailed => HsmErrorKind::AuthenticationFailed,
            ResponseCode::DeviceSessionsFull => HsmErrorKind::SessionsFull,
            ResponseCode::DeviceSessionFailed => HsmErrorKind::SessionFailed,
            ResponseCode::DeviceStorageFailed => HsmErrorKind::StorageFailed,
            ResponseCode::DeviceWrongLength => HsmErrorKind::WrongLength,
            ResponseCode::DeviceInsufficientPermissions => HsmErrorKind::InsufficientPermissions,
            ResponseCode::DeviceLogFull => HsmErrorKind::LogFull,
            ResponseCode::DeviceObjectNotFound => HsmErrorKind::ObjectNotFound,
            ResponseCode::DeviceInvalidId => HsmErrorKind::InvalidId,
            ResponseCode::DeviceInvalidOtp => HsmErrorKind::InvalidOtp,
            ResponseCode::DeviceDemoMode => HsmErrorKind::DemoMode,
            ResponseCode::DeviceCommandUnexecuted => HsmErrorKind::CommandUnexecuted,
            ResponseCode::GenericError => HsmErrorKind::GenericError,
            ResponseCode::DeviceObjectExists => HsmErrorKind::ObjectExists,
            ResponseCode::DeviceSshCaConstraintViolation => HsmErrorKind::SshCaConstraintViolation,
            _ => return None,
        })
    }

    /// Create an `HsmError` from the given `ResponseMessage` (if applicable)
    pub(crate) fn from_response_message(response: &ResponseMessage) -> Option<HsmErrorKind> {
        if response.is_err() && response.data.len() == 1 {
            Some(HsmErrorKind::from_u8(response.data[0]))
        } else {
            None
        }
    }
}

/// Create a new error (of a given kind) with a formatted message
macro_rules! err {
    ($kind:path, $msg:expr) => {
        crate::error::Error::new($kind, Some($msg.to_string()))
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        err!($kind, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:path, $msg:expr) => {
        return Err(err!($kind, $msg).into());
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, &format!($fmt, $($arg)+));
    };
}

/// Assert a condition is true, returning an error type with a formatted message if not
macro_rules! ensure {
    ($cond:expr, $kind:path, $msg:expr) => {
        if !($cond) {
            return Err(err!($kind, $msg).into());
        }
    };
    ($cond:expr, $kind:path, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err(err!($kind, $fmt, $($arg)+).into());
        }
    };
}
