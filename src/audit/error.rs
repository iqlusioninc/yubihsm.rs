use std::fmt;

/// Audit-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of audit-related errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Invalid option
    OptionInvalid,

    /// Invalid tag
    TagInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::OptionInvalid => "invalid option",
            ErrorKind::TagInvalid => "invalid tag",
        })
    }
}
