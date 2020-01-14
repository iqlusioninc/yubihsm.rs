//! YubiHSM client errors

use crate::{connector, device, serialization, session};
use anomaly::{BoxError, Context};
use std::io;
use thiserror::Error;

/// Client errors
pub type Error = crate::Error<ErrorKind>;

/// Client error kinds
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    #[error("authentication failed")]
    AuthenticationError,

    /// Session is closed
    #[error("session closed")]
    ClosedSessionError,

    /// Errors with the connection to the HSM
    #[error("connector error")]
    ConnectorError,

    /// Couldn't create session
    #[error("couldn't create session")]
    CreateFailed,

    /// Errors originating in the HSM device
    #[error("HSM error")]
    DeviceError,

    /// Protocol error occurred
    #[error("protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[error("HSM response error")]
    ResponseError,
}

impl Error {
    /// Get the device error, if this is a device error
    pub fn device_error(&self) -> Option<device::ErrorKind> {
        // TODO(tarcieri): eliminate unwraps or double check they will never panic
        use std::error::Error;
        if let Some(session_err) = self.source()?.downcast_ref::<session::Error>() {
            session_err.source()?.downcast_ref().cloned()
        } else {
            None
        }
    }
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        ErrorKind::ConnectorError.context(err).into()
    }
}

impl From<session::Error> for Error {
    fn from(err: session::Error) -> Self {
        let kind = match err.kind() {
            session::ErrorKind::AuthenticationError => ErrorKind::AuthenticationError,
            session::ErrorKind::ClosedError => ErrorKind::ClosedSessionError,
            session::ErrorKind::CreateFailed => ErrorKind::CreateFailed,
            session::ErrorKind::DeviceError => ErrorKind::DeviceError,
            session::ErrorKind::ProtocolError
            | session::ErrorKind::CommandLimitExceeded
            | session::ErrorKind::MismatchError
            | session::ErrorKind::VerifyFailed => ErrorKind::ProtocolError,
            session::ErrorKind::ResponseError => ErrorKind::ResponseError,
        };

        kind.context(err).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        ErrorKind::ProtocolError.context(err).into()
    }
}

impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        ErrorKind::ProtocolError.context(err).into()
    }
}

impl From<Error> for signature::Error {
    fn from(client_error: Error) -> signature::Error {
        signature::Error::from_source(client_error)
    }
}
