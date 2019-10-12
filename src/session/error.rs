//! Session error types

use crate::{connector, device, serialization};
use std::fmt;

/// Session errors
pub type Error = crate::Error<ErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    AuthenticationError,

    /// Session is closed
    ClosedError,

    /// Max command per session exceeded and a new session should be created
    CommandLimitExceeded,

    /// Couldn't create session
    CreateFailed,

    /// Errors originating in the HSM device
    DeviceError {
        /// HSM error kind
        kind: device::ErrorKind,
    },

    /// Message was intended for a different session than the current one
    MismatchError,

    /// Protocol error occurred
    ProtocolError,

    /// Error response from HSM we can't further specify
    ResponseError,

    /// MAC or cryptogram verify failed
    VerifyFailed,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::AuthenticationError => f.write_str("authentication failed"),
            ErrorKind::ClosedError => f.write_str("session closed"),
            ErrorKind::CommandLimitExceeded => f.write_str("max commands per session exceeded"),
            ErrorKind::CreateFailed => f.write_str("couldn't create session"),
            ErrorKind::DeviceError { kind } => write!(f, "HSM error: {}", kind),
            ErrorKind::MismatchError => f.write_str("message has differing session ID"),
            ErrorKind::ProtocolError => f.write_str("protocol error"),
            ErrorKind::ResponseError => f.write_str("HSM error"),
            ErrorKind::VerifyFailed => f.write_str("verification failed"),
        }
    }
}

impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        format_err!(ErrorKind::ProtocolError, err.to_string())
    }
}

impl From<device::ErrorKind> for Error {
    fn from(kind: device::ErrorKind) -> Self {
        Error::new(ErrorKind::DeviceError { kind }, None)
    }
}

impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        format_err!(ErrorKind::ProtocolError, err.to_string())
    }
}
