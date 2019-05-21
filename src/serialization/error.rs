use crate::error::Error;
use failure::Fail;
use serde;
use std::{fmt, io};

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

impl serde::ser::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(SerializationErrorKind::Parse, msg.to_string())
    }
}

impl serde::de::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(SerializationErrorKind::Parse, msg.to_string())
    }
}

impl From<io::Error> for SerializationError {
    fn from(err: io::Error) -> Self {
        err!(SerializationErrorKind::Io, err.to_string())
    }
}
