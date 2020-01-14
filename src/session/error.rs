//! Session error types

use crate::{connector, device, serialization};
use anomaly::{BoxError, Context};
use thiserror::Error;

/// Session errors
pub type Error = crate::Error<ErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    #[error("authentication failed")]
    AuthenticationError,

    /// Session is closed
    #[error("session closed")]
    ClosedError,

    /// Max command per session exceeded and a new session should be created
    #[error("max commands per session exceeded")]
    CommandLimitExceeded,

    /// Couldn't create session
    #[error("couldn't create session")]
    CreateFailed,

    /// Errors originating in the HSM device
    #[error("HSM error")]
    DeviceError,

    /// Message was intended for a different session than the current one
    #[error("session ID mismatch")]
    MismatchError,

    /// Protocol error occurred
    #[error("protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[error("HSM response error")]
    ResponseError,

    /// MAC or cryptogram verify failed
    #[error("cryptographic verification failed")]
    VerifyFailed,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        ErrorKind::ProtocolError.context(err).into()
    }
}

impl From<device::ErrorKind> for Error {
    fn from(kind: device::ErrorKind) -> Self {
        ErrorKind::DeviceError.context(kind).into()
    }
}

impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        ErrorKind::ProtocolError.context(err).into()
    }
}
