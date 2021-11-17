//! Key wrapping errors

use crate::error::{BoxError, Context};
use thiserror::Error;

/// Wrap-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of wrap-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Wrap message is an invalid length
    #[error("invalid message length")]
    LengthInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
