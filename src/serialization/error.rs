//! Serialization errors

use anomaly::{format_err, BoxError, Context};
use serde::{de, ser};
use std::{fmt, io};
use thiserror::Error;

/// Serialization errors
pub type Error = crate::Error<ErrorKind>;

/// Serialization errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Input/output errors
    #[error("I/O error")]
    Io,

    /// Errors that occurred during Serde parsing
    #[error("parse error")]
    Parse,

    /// Unexpected end-of-buffer/file
    #[error("unexpected end of buffer")]
    UnexpectedEof,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        format_err!(ErrorKind::Parse, msg.to_string()).into()
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        format_err!(ErrorKind::Parse, msg.to_string()).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        ErrorKind::Io.context(err).into()
    }
}
