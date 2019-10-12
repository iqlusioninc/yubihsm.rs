use std::fmt;

/// `MockHsm`-related errors
pub type Error = crate::Error<ErrorKind>;

/// Kinds of `MockHsm`-related errors
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Access denied
    AccessDenied,

    /// Crypto error
    CryptoError,

    /// Object does not exist
    ObjectNotFound,

    /// Unsupported algorithm
    UnsupportedAlgorithm,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::AccessDenied => "access denied",
            ErrorKind::CryptoError => "crypto error",
            ErrorKind::ObjectNotFound => "object not found",
            ErrorKind::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}
