//! Error types for Secure Channel communications

use adapters::AdapterError;
use error::Error;

/// Secure Channel errors
pub type SecureChannelError = Error<SecureChannelErrorKind>;

/// Secure Channel error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SecureChannelErrorKind {
    /// Protocol error (i.e. parse error)
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Max commands per session exceeded and a new session should be created
    #[fail(display = "session limit reached")]
    SessionLimitReached,

    /// Message was intended for a different session than the current one
    #[fail(display = "message has differing session ID")]
    SessionMismatch,

    /// MAC or cryptogram verify failed
    #[fail(display = "verification failed")]
    VerifyFailed,
}

impl From<AdapterError> for SecureChannelError {
    fn from(err: AdapterError) -> Self {
        err!(SecureChannelErrorKind::ProtocolError, err.to_string())
    }
}
