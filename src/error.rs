pub use failure::{Backtrace, Context, Fail};
use std::error::Error as StdError;
use std::fmt::{self, Display};

use response::ResponseCode;
use securechannel::ResponseMessage;

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.description {
            Some(ref desc) => write!(f, "{}: {}", &self.inner, desc),
            None => Display::fmt(&self.inner, f),
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
            None => "(no description)",
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
    CommandInvalid,

    /// Invalid data
    #[fail(display = "invalid data")]
    DataInvalid,

    /// Invalid session
    #[fail(display = "invalid session")]
    SessionInvalid,

    /// Authentication failure
    #[fail(display = "authentication failed")]
    AuthFail,

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

    /// Invalid permissions
    #[fail(display = "invalid permissions")]
    PermissionInvalid,

    /// Audit log full
    #[fail(display = "audit log full")]
    LogFull,

    /// Object not found
    #[fail(display = "object not found")]
    ObjectNotFound,
}

impl HsmErrorKind {
    /// Create an `HsmErrorKind` from the given byte tag
    pub fn from_u8(tag: u8) -> HsmErrorKind {
        match tag {
            0x01 => HsmErrorKind::CommandInvalid,
            0x02 => HsmErrorKind::DataInvalid,
            0x03 => HsmErrorKind::SessionInvalid,
            0x04 => HsmErrorKind::AuthFail,
            0x05 => HsmErrorKind::SessionsFull,
            0x06 => HsmErrorKind::SessionFailed,
            0x07 => HsmErrorKind::StorageFailed,
            0x08 => HsmErrorKind::WrongLength,
            0x09 => HsmErrorKind::PermissionInvalid,
            0x0a => HsmErrorKind::LogFull,
            0x0b => HsmErrorKind::ObjectNotFound,
            code => HsmErrorKind::Unknown { code },
        }
    }

    /// Serialize this `HsmErrorKind` as a byte tag
    pub fn to_u8(self) -> u8 {
        match self {
            HsmErrorKind::Unknown { code } => code,
            HsmErrorKind::CommandInvalid => 0x01,
            HsmErrorKind::DataInvalid => 0x02,
            HsmErrorKind::SessionInvalid => 0x03,
            HsmErrorKind::AuthFail => 0x04,
            HsmErrorKind::SessionsFull => 0x05,
            HsmErrorKind::SessionFailed => 0x06,
            HsmErrorKind::StorageFailed => 0x07,
            HsmErrorKind::WrongLength => 0x08,
            HsmErrorKind::PermissionInvalid => 0x09,
            HsmErrorKind::LogFull => 0x0a,
            HsmErrorKind::ObjectNotFound => 0x0b,
        }
    }

    /// Create an `HsmError` from the given `ResponseCode` (if applicable)
    pub fn from_response_code(code: ResponseCode) -> Option<HsmErrorKind> {
        Some(match code {
            ResponseCode::DeviceInvalidCommand => HsmErrorKind::CommandInvalid,
            ResponseCode::DeviceInvalidData => HsmErrorKind::DataInvalid,
            ResponseCode::DeviceInvalidSession => HsmErrorKind::SessionInvalid,
            ResponseCode::DeviceAuthFail => HsmErrorKind::AuthFail,
            ResponseCode::DeviceSessionsFull => HsmErrorKind::SessionsFull,
            ResponseCode::DeviceSessionFailed => HsmErrorKind::SessionFailed,
            ResponseCode::DeviceStorageFailed => HsmErrorKind::StorageFailed,
            ResponseCode::DeviceWrongLength => HsmErrorKind::WrongLength,
            ResponseCode::DeviceInvalidPermission => HsmErrorKind::PermissionInvalid,
            ResponseCode::DeviceLogFull => HsmErrorKind::LogFull,
            ResponseCode::DeviceObjNotFound => HsmErrorKind::ObjectNotFound,
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
        ::error::Error::new($kind, Some($msg.to_string()))
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
