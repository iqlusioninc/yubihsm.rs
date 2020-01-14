//! Object errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// `Object`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `Object`-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Invalid label
    #[error("invalid label")]
    LabelInvalid,

    /// Invalid object origin
    #[error("invalid object origin")]
    OriginInvalid,

    /// Invalid object type
    #[error("invalid object type")]
    TypeInvalid,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
