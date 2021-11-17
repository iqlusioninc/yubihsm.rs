//! Domain errors

use crate::error::{BoxError, Context};
use thiserror::Error;

/// Audit-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of audit-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Invalid domain
    #[error("invalid domain")]
    DomainInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
