//! Authentication errors

use crate::Error;

/// `authentication::Key`-related errors
pub type KeyError = Error<KeyErrorKind>;

/// Kinds of `authentication::Key`-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum KeyErrorKind {
    /// Size is invalid
    #[fail(display = "invalid size")]
    SizeInvalid,
}
