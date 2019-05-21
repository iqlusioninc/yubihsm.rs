//! Session error types

use crate::{
    connector::ConnectionError, device::DeviceErrorKind, error::Error,
    serialization::SerializationError,
};
use failure::Fail;

/// Session errors
pub type SessionError = Error<SessionErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SessionErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthenticationError,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedSessionError,

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
        kind: DeviceErrorKind,
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

impl From<ConnectionError> for SessionError {
    fn from(err: ConnectionError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<DeviceErrorKind> for SessionError {
    fn from(kind: DeviceErrorKind) -> Self {
        SessionError::new(SessionErrorKind::DeviceError { kind }, None)
    }
}

impl From<SerializationError> for SessionError {
    fn from(err: SerializationError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}
