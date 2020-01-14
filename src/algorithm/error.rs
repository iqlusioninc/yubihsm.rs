//! Algorithm errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// `Algorithm`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `Algorithm`-related errors
#[derive(Copy, Clone, Eq, Error, PartialEq, Debug)]
pub enum ErrorKind {
    /// Invalid algorithm tag
    #[error("invalid tag")]
    TagInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
