//! Authentication errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// Authentication errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of authentication errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Key size is invalid
    #[error("invalid key size")]
    KeySizeInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
