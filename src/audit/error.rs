//! Audit errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// Audit-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of audit-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Invalid option
    #[error("invalid option")]
    OptionInvalid,

    /// Invalid tag
    #[error("invalid tag")]
    TagInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
