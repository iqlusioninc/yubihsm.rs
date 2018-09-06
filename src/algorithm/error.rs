//! `Algorithm`-related errors

use error::Error;

/// `Algorithm`-related errors
pub type AlgorithmError = Error<AlgorithmErrorKind>;

/// Kinds of `Algorithm`-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum AlgorithmErrorKind {
    /// Size is invalid
    #[fail(display = "invalid size")]
    SizeInvalid,
}
