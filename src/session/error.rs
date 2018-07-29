//! Errors that occur during sessions

use connector::ConnectorError;
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

/// Create a new Session error with a formatted message
macro_rules! session_err {
    ($kind:ident, $msg:expr) => {
        ::session::SessionError::new(
            ::session::SessionErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        session_err!($kind, format!($fmt, $($arg)+))
    };
}

/// Create and return a Session error with a formatted message
macro_rules! session_fail {
    ($kind:ident, $msg:expr) => {
        return Err(session_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(session_err!($kind, $fmt, $($arg)+).into());
    };
}

impl From<ConnectorError> for SessionError {
    fn from(err: ConnectorError) -> Self {
        session_err!(ProtocolError, err.to_string())
    }
}

impl From<SecureChannelError> for SessionError {
    fn from(err: SecureChannelError) -> Self {
        session_err!(ProtocolError, err.to_string())
    }
}

impl From<SerializationError> for SessionError {
    fn from(err: SerializationError) -> Self {
        session_err!(ProtocolError, err.to_string())
    }
}
