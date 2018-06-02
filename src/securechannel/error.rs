//! Error types for Secure Channel communications

use connector::ConnectorError;
use error::Error;

/// Secure Channel errors
pub type SecureChannelError = Error<SecureChannelErrorKind>;

/// Secure Channel error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SecureChannelErrorKind {
    /// MAC or cryptogram verify failed
    #[fail(display = "verification failed")]
    VerifyFailed,

    /// Protocol error (i.e. parse error)
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Max commands per session exceeded and a new session should be created
    #[fail(display = "session limit reached")]
    SessionLimitReached,
}

/// Create a new Secure Channel error with a formatted message
macro_rules! secure_channel_err {
    ($kind:ident, $msg:expr) => {
        ::securechannel::SecureChannelError::new(
            ::securechannel::SecureChannelErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        ::securechannel::SecureChannelError::new(
            ::securechannel::SecureChannelErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

/// Create and return a Secure Channel error with a formatted message
macro_rules! secure_channel_fail {
    ($kind:ident, $msg:expr) => {
        return Err(secure_channel_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(secure_channel_err!($kind, $fmt, $($arg)+).into());
    };
}

/// Assert a condition is true, returning an error type with a formatted message if not
macro_rules! secure_channel_ensure {
    ($condition:expr, $kind:ident, $msg:expr) => {
        if !($condition) {
            secure_channel_fail!($kind, $msg);
        }
    };
    ($condition:expr, $kind:ident, $fmt:expr, $($arg:tt)+) => {
        if !($condition) {
            secure_channel_fail!($kind, $fmt, $($arg)+);
        }
    };
}

impl From<ConnectorError> for SecureChannelError {
    fn from(err: ConnectorError) -> Self {
        secure_channel_err!(ProtocolError, err.to_string())
    }
}
