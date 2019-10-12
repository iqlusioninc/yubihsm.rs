//! Error types

use std::fmt::{self, Debug, Display};

/// Error types used by this library
#[derive(Debug)]
pub struct Error<K>
where
    K: Copy + Debug + Display + PartialEq + Eq,
{
    /// Kind of error
    kind: K,

    /// Optional associated error message
    msg: Option<String>,
}

impl<K> Error<K>
where
    K: Copy + Debug + Display + PartialEq + Eq,
{
    /// Create a new error type from its kind
    pub fn new(kind: K, msg: Option<String>) -> Self {
        Self { kind, msg }
    }

    /// Obtain the error's `Kind`
    pub fn kind(&self) -> K {
        self.kind
    }
}

impl<K> Display for Error<K>
where
    K: Copy + Debug + Display + PartialEq + Eq,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;

        if let Some(msg) = &self.msg {
            write!(f, ": {}", msg)?;
        }

        Ok(())
    }
}

impl<K> std::error::Error for Error<K> where K: Copy + Debug + Display + PartialEq + Eq {}

/// Create a new error (of a given kind) with a formatted message
macro_rules! format_err {
    ($kind:path, $msg:expr) => {
        crate::error::Error::new($kind, Some($msg.to_string()))
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        format_err!($kind, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:path, $msg:expr) => {
        return Err(format_err!($kind, $msg).into());
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, &format!($fmt, $($arg)+));
    };
}

/// Assert a condition is true, returning an error type with a formatted message if not
macro_rules! ensure {
    ($cond:expr, $kind:path, $msg:expr) => {
        if !($cond) {
            return Err(format_err!($kind, $msg).into());
        }
    };
    ($cond:expr, $kind:path, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err(format_err!($kind, $fmt, $($arg)+).into());
        }
    };
}
