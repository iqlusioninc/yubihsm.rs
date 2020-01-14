//! YubiHSM setup errors

use anomaly::{BoxError, Context};
use thiserror::Error;

/// Setup-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of setup-related errors
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Invalid label
    #[error("invalid label")]
    LabelInvalid,

    /// Errors involving setup report generation
    #[error("report failed")]
    ReportFailed,

    /// Error performing setup
    #[error("setup failed")]
    SetupFailed,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl From<crate::client::Error> for Error {
    fn from(client_error: crate::client::Error) -> Error {
        ErrorKind::SetupFailed.context(client_error).into()
    }
}
