use std::fmt;

/// Audit-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of audit-related errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Invalid domain
    DomainInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::DomainInvalid => "invalid domain",
        })
    }
}
