use std::fmt;

/// `Object`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `Object`-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Invalid label
    LabelInvalid,

    /// Invalid object origin
    OriginInvalid,

    /// Invalid object type
    TypeInvalid,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::LabelInvalid => "invalid label",
            ErrorKind::OriginInvalid => "invalid object origin",
            ErrorKind::TypeInvalid => "invalid object type",
        })
    }
}
