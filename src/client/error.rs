//! YubiHSM client errors

use crate::{connector, device, serialization, session};
use failure::Fail;
use std::{error::Error as StdError, io};

/// Client errors
pub type Error = crate::Error<ErrorKind>;

/// Client error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthenticationError,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedSessionError,

    /// Errors with the connection to the HSM
    #[fail(display = "connection error")]
    ConnectorError {
        /// Connection error kind
        kind: connector::ErrorKind,
    },

    /// Couldn't create session
    #[fail(display = "couldn't create session")]
    CreateFailed,

    /// Errors originating in the HSM device
    #[fail(display = "HSM error: {}", kind)]
    DeviceError {
        /// HSM error kind
        kind: device::ErrorKind,
    },

    /// Protocol error occurred
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[fail(display = "HSM error")]
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

// TODO: capture causes?
impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        let kind = ErrorKind::ConnectorError { kind: err.kind() };
        err!(kind, err.description())
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

        err!(kind, err.description())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        err!(ErrorKind::ProtocolError, err.description())
    }
}

// TODO: capture causes?
impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        err!(ErrorKind::ProtocolError, err.description())
    }
}

impl From<Error> for signatory::Error {
    fn from(client_error: Error) -> signatory::Error {
        signatory::Error::from_cause(client_error)
    }
}
