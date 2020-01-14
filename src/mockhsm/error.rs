//! MockHSM errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// `MockHsm`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `MockHsm`-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Access denied
    #[error("access denied")]
    AccessDenied,

    /// Crypto error
    #[error("crypto error")]
    CryptoError,

    /// Object does not exist
    #[error("object not found")]
    ObjectNotFound,

    /// Unsupported algorithm
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
