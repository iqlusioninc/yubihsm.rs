use std::fmt;

/// Response-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of response-related errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Invalid code
    CodeInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::CodeInvalid => "invalid code",
        })
    }
}
