//! Errors that occur during sessions

use adapters::AdapterError;
use error::{Error, HsmErrorKind};
use securechannel::SecureChannelError;
use serializers::SerializationError;

/// Session errors
pub type SessionError = Error<SessionErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SessionErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthFail,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedSessionError,

    /// Couldn't create session
    #[fail(display = "couldn't create session")]
    CreateFailed,

    /// Errors originating in the HSM device
    #[fail(display = "HSM error: {}", kind)]
    DeviceError {
        /// HSM error kind
        kind: HsmErrorKind,
    },

    /// Protocol error occurred
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[fail(display = "HSM error")]
    ResponseError,

    /// Session with HSM failed
    #[fail(display = "session failed")]
    SessionFailed,

    /// Session with HSM invalid
    #[fail(display = "invalid session")]
    SessionInvalid,

    /// HSM exceeded maximum number of sessions (16)
    #[fail(display = "HSM sessions full (max 16)")]
    SessionsFull,

    /// HSM storage failure
    #[fail(display = "HSM storage failure")]
    StorageFailed,

    /// Session with the YubiHSM2 timed out
    #[fail(display = "session timeout")]
    TimeoutError,

    /// Length incorrect for operation
    #[fail(display = "wrong length")]
    WrongLength,
}

impl From<AdapterError> for SessionError {
    fn from(err: AdapterError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<HsmErrorKind> for SessionError {
    fn from(kind: HsmErrorKind) -> Self {
        SessionError::new(SessionErrorKind::DeviceError { kind }, None)
    }
}

impl From<SecureChannelError> for SessionError {
    fn from(err: SecureChannelError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<SerializationError> for SessionError {
    fn from(err: SerializationError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}
