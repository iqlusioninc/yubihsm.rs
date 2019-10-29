//! YubiHSM client errors

use crate::{connector, device, serialization, session};
use std::{fmt, io};

/// Client errors
pub type Error = crate::Error<ErrorKind>;

/// Client error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    AuthenticationError,

    /// Session is closed
    ClosedSessionError,

    /// Errors with the connection to the HSM
    ConnectorError {
        /// Connection error kind
        kind: connector::ErrorKind,
    },

    /// Couldn't create session
    CreateFailed,

    /// Errors originating in the HSM device
    DeviceError {
        /// HSM error kind
        kind: device::ErrorKind,
    },

    /// Protocol error occurred
    ProtocolError,

    /// Error response from HSM we can't further specify
    ResponseError,
}

impl ErrorKind {
    /// Get the device error, if this is a device error
    pub fn device_error(self) -> Option<device::ErrorKind> {
        match self {
            ErrorKind::DeviceError { kind } => Some(kind),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::AuthenticationError => f.write_str("authentication failed"),
            ErrorKind::ClosedSessionError => f.write_str("session closed"),
            ErrorKind::ConnectorError { kind } => write!(f, "connection error: {}", kind),
            ErrorKind::CreateFailed => f.write_str("couldn't create session"),
            ErrorKind::DeviceError { kind } => write!(f, "HSM error: {}", kind),
            ErrorKind::ProtocolError => f.write_str("protocol error"),
            ErrorKind::ResponseError => f.write_str("HSM error"),
        }
    }
}

// TODO: capture causes?
impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        let kind = ErrorKind::ConnectorError { kind: err.kind() };
        format_err!(kind, "{}", err)
    }
}

// TODO: capture causes?
impl From<session::Error> for Error {
    fn from(err: session::Error) -> Self {
        let kind = match err.kind() {
            session::ErrorKind::AuthenticationError => ErrorKind::AuthenticationError,
            session::ErrorKind::ClosedError => ErrorKind::ClosedSessionError,
            session::ErrorKind::CreateFailed => ErrorKind::CreateFailed,
            session::ErrorKind::DeviceError { kind } => ErrorKind::DeviceError { kind },
            session::ErrorKind::ProtocolError
            | session::ErrorKind::CommandLimitExceeded
            | session::ErrorKind::MismatchError
            | session::ErrorKind::VerifyFailed => ErrorKind::ProtocolError,
            session::ErrorKind::ResponseError => ErrorKind::ResponseError,
        };

        format_err!(kind, "{}", err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        format_err!(ErrorKind::ProtocolError, "{}", err)
    }
}

// TODO: capture causes?
impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        format_err!(ErrorKind::ProtocolError, "{}", err)
    }
}

impl From<Error> for signature::Error {
    fn from(client_error: Error) -> signature::Error {
        signature::Error::from_source(client_error)
    }
}
