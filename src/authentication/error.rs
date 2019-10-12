use std::fmt;

/// Authentication errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of authentication errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Key size is invalid
    KeySizeInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::KeySizeInvalid => "invalid key size",
        })
    }
}
