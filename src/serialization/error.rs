//! Serialization erros

use serde::{de, ser};
use std::{fmt, io};

/// Serialization errors
pub type Error = crate::Error<ErrorKind>;

/// Serialization errors
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Input/output errors
    Io,

    /// Errors that occurred during Serde parsing
    Parse,

    /// Unexpected end-of-buffer/file
    UnexpectedEof,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::Io => "I/O error",
            ErrorKind::Parse => "parse error",
            ErrorKind::UnexpectedEof => "unexpected end of buffer",
        })
    }
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        format_err!(ErrorKind::Parse, msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        format_err!(ErrorKind::Parse, msg.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        format_err!(ErrorKind::Io, err.to_string())
    }
}
