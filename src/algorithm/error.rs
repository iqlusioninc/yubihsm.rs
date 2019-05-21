//! `Algorithm`-related errors

use crate::error::Error;
use failure::Fail;

/// `Algorithm`-related errors
pub type AlgorithmError = Error<AlgorithmErrorKind>;

/// Kinds of `Algorithm`-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum AlgorithmErrorKind {
    /// Invalid algorithm tag
    #[fail(display = "invalid tag")]
    TagInvalid,
}
