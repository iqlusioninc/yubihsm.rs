use serde;
use std::{fmt, io};

use error::Error;

/// Serialization errors
pub type SerializationError = Error<SerializationErrorKind>;

/// Serialization errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SerializationErrorKind {
    /// Input/output errors
    #[fail(display = "I/O error")]
    Io,

    /// Errors that occurred during Serde parsing
    #[fail(display = "parse error")]
    Parse,

    /// Unexpected end-of-buffer/file
    #[fail(display = "unexpected end of buffer")]
    UnexpectedEof,
}

/// Create a new serialization error with a formatted message
macro_rules! serialization_err {
    ($kind:ident, $msg:expr) => {
        SerializationError::new(
            ::serializers::SerializationErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        SerializationError::new(
            ::serializers::SerializationErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

impl serde::ser::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        serialization_err!(Parse, msg.to_string())
    }
}

impl serde::de::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        serialization_err!(Parse, msg.to_string())
    }
}

impl From<io::Error> for SerializationError {
    fn from(err: io::Error) -> Self {
        serialization_err!(Io, err.to_string())
    }
}
