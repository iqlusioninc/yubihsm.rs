//! Error types for yubihsm-connector

use std::num::ParseIntError;
use std::str::Utf8Error;
use std::{fmt, io};

use error::Error;

/// yubihsm-connector related errors
pub type ConnectorError = Error<ConnectorErrorKind>;

/// yubihsm-connector related error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ConnectorErrorKind {
    /// URL provided for yubihsm-connector is not valid
    #[fail(display = "invalid URL")]
    InvalidURL,

    /// Connection to yubihsm-connector failed
    #[fail(display = "connection failed")]
    ConnectionFailed,

    /// Input/output error
    #[fail(display = "I/O error")]
    IoError,

    /// Error making request
    #[fail(display = "invalid request")]
    RequestError,

    /// yubihsm-connector sent bad response
    #[fail(display = "bad connector response")]
    ResponseError,
}

/// Create a new connector error with a formatted message
macro_rules! connector_err {
    ($kind:ident, $msg:expr) => {
        ::connector::ConnectorError::new(
            ::connector::ConnectorErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        ::connector::ConnectorError::new(
            ::connector::ConnectorErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

/// Create and return an connector error with a formatted message
macro_rules! connector_fail {
    ($kind:ident, $msg:expr) => {
        return Err(connector_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(connector_err!($kind, $fmt, $($arg)+).into());
    };
}

impl From<fmt::Error> for ConnectorError {
    fn from(err: fmt::Error) -> Self {
        connector_err!(IoError, err.to_string())
    }
}

impl From<io::Error> for ConnectorError {
    fn from(err: io::Error) -> Self {
        connector_err!(IoError, err.to_string())
    }
}

impl From<ParseIntError> for ConnectorError {
    fn from(err: ParseIntError) -> Self {
        connector_err!(ResponseError, err.to_string())
    }
}

impl From<Utf8Error> for ConnectorError {
    fn from(err: Utf8Error) -> Self {
        connector_err!(ResponseError, err.to_string())
    }
}
