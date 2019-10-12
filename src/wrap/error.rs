use std::fmt;

/// Wrap-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of wrap-related errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Wrap message is an invalid length
    LengthInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::LengthInvalid => "invalid message length",
        })
    }
}
