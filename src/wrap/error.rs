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

    /// RSA key did not have 2 primes - multi-primes are not supported
    #[error("RSA key did not have 2 primes")]
    InvalidPrimes,

    /// RSA precomputation failed
    #[error("RSA precomputation failed")]
    RsaPrecomputeFailed,

    /// Unsupported key size
    #[error("unsupported key size")]
    UnsupportedKeySize,

    /// Wrapping key algorithm mismatch
    #[error("Wrap key algorithm mismatch")]
    AlgorithmMismatch,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}
