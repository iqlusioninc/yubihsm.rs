//! Error types for `yubihsm-connector`

use std::num::ParseIntError;
use std::str::Utf8Error;
use std::{fmt, io};

use error::Error;

/// `yubihsm-connector` related errors
pub type AdapterError = Error<AdapterErrorKind>;

/// `yubihsm-connector` related error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum AdapterErrorKind {
    /// URL provided for `yubihsm-connector` is not valid
    #[fail(display = "invalid URL")]
    InvalidURL,

    /// Connection to `yubihsm-connector` failed
    #[fail(display = "connection failed")]
    ConnectionFailed,

    /// Input/output error
    #[fail(display = "I/O error")]
    IoError,

    /// Error making request
    #[fail(display = "invalid request")]
    RequestError,

    /// `yubihsm-connector` sent bad response
    #[fail(display = "bad connector response")]
    ResponseError,
}

/// Create a new connector error with a formatted message
macro_rules! adapter_err {
    ($kind:ident, $msg:expr) => {
        ::adapters::AdapterError::new(
            ::adapters::AdapterErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        ::adapters::AdapterError::new(
            ::adapters::AdapterErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

/// Create and return an connector error with a formatted message
macro_rules! adapter_fail {
    ($kind:ident, $msg:expr) => {
        return Err(adapter_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(adapter_err!($kind, $fmt, $($arg)+).into());
    };
}

impl From<fmt::Error> for AdapterError {
    fn from(err: fmt::Error) -> Self {
        adapter_err!(IoError, err.to_string())
    }
}

impl From<io::Error> for AdapterError {
    fn from(err: io::Error) -> Self {
        adapter_err!(IoError, err.to_string())
    }
}

impl From<ParseIntError> for AdapterError {
    fn from(err: ParseIntError) -> Self {
        adapter_err!(ResponseError, err.to_string())
    }
}

impl From<Utf8Error> for AdapterError {
    fn from(err: Utf8Error) -> Self {
        adapter_err!(ResponseError, err.to_string())
    }
}
