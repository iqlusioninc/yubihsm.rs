use std::fmt;

/// Setup-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of setup-related errors
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Invalid label
    LabelInvalid,

    /// Errors involving setup report generation
    ReportFailed,

    /// Error performing setup
    SetupFailed,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::LabelInvalid => "invalid label",
            ErrorKind::ReportFailed => "report failed",
            ErrorKind::SetupFailed => "setup failed",
        })
    }
}

impl From<crate::client::Error> for Error {
    fn from(client_error: crate::client::Error) -> Error {
        // TODO(tarcieri): finer grained error reporting / ErrorKind mapping?
        format_err!(ErrorKind::SetupFailed, "{}", client_error)
    }
}
