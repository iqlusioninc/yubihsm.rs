//! Response errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// Response-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of response-related errors
#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub enum ErrorKind {
    /// Invalid code
    #[error("invalid code")]
    CodeInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
