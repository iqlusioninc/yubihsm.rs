//! Serialization erros

use failure::Fail;
use serde;
use std::{fmt, io};

/// Serialization errors
pub type Error = crate::Error<ErrorKind>;

/// Serialization errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
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

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(ErrorKind::Parse, msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(ErrorKind::Parse, msg.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        err!(ErrorKind::Io, err.to_string())
    }
}
