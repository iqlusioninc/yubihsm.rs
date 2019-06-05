//! Session error types

use crate::{connector, device, serialization};
use failure::Fail;

/// Session errors
pub type Error = crate::Error<ErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthenticationError,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedError,

    /// Max command per session exceeded and a new session should be created
    #[fail(display = "max commands per session exceeded")]
    CommandLimitExceeded,

    /// Couldn't create session
    #[fail(display = "couldn't create session")]
    CreateFailed,

    /// Errors originating in the HSM device
    #[fail(display = "HSM error: {}", kind)]
    DeviceError {
        /// HSM error kind
        kind: device::ErrorKind,
    },

    /// Message was intended for a different session than the current one
    #[fail(display = "message has differing session ID")]
    MismatchError,

    /// Protocol error occurred
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[fail(display = "HSM error")]
    ResponseError,

    /// MAC or cryptogram verify failed
    #[fail(display = "verification failed")]
    VerifyFailed,
}

impl From<connector::Error> for Error {
    fn from(err: connector::Error) -> Self {
        err!(ErrorKind::ProtocolError, err.to_string())
    }
}

impl From<device::ErrorKind> for Error {
    fn from(kind: device::ErrorKind) -> Self {
        Error::new(ErrorKind::DeviceError { kind }, None)
    }
}

impl From<serialization::Error> for Error {
    fn from(err: serialization::Error) -> Self {
        err!(ErrorKind::ProtocolError, err.to_string())
    }
}
