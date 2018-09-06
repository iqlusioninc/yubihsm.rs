//! Errors that occur during sessions

use adapters::AdapterError;
use error::Error;
use securechannel::SecureChannelError;
use serializers::SerializationError;

/// Session errors
pub type SessionError = Error<SessionErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SessionErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthFailed,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedSessionError,

    /// Couldn't create session
    #[fail(display = "couldn't create session")]
    CreateFailed,

    /// Protocol error occurred
    #[fail(display = "protocol error")]
    ProtocolError,

    /// HSM returned an error response
    #[fail(display = "bad HSM response")]
    ResponseError,

    /// Session with the YubiHSM2 timed out
    #[fail(display = "session timeout")]
    TimeoutError,
}

impl From<AdapterError> for SessionError {
    fn from(err: AdapterError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
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
