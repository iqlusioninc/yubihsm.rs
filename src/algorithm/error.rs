//! `Algorithm`-related errors

use failure::Fail;

/// `Algorithm`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `Algorithm`-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Invalid algorithm tag
    #[fail(display = "invalid tag")]
    TagInvalid,
}
