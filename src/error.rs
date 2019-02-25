//! Error types

pub use failure::{Backtrace, Context, Fail};
use std::{
    error::Error as StdError,
    fmt::{self, Display},
};

/// Placeholder for when we have no description for an error
const NO_DESCRIPTION: &str = "(no description)";

/// Error types used by this library
#[derive(Debug)]
pub struct Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    inner: Context<T>,
    description: Option<String>,
}

impl<T> Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    /// Create a new error type from its kind
    pub fn new(kind: T, description: Option<String>) -> Self {
        Self {
            inner: Context::new(kind),
            description,
        }
    }

    /// Obtain the error's `Kind`
    pub fn kind(&self) -> T {
        *self.inner.get_context()
    }
}

impl<T> Display for Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.description {
            None => Display::fmt(&self.inner, f),
            Some(ref desc) => {
                if desc == NO_DESCRIPTION {
                    Display::fmt(&self.inner, f)
                } else {
                    write!(f, "{}: {}", &self.inner, desc)
                }
            }
        }
    }
}

impl<T> StdError for Error<T>
where
    T: Copy + Display + Fail + PartialEq + Eq,
{
    /// Obtain the error's description
    fn description(&self) -> &str {
        match self.description {
            Some(ref s) => s,
            None => NO_DESCRIPTION,
        }
    }
}

/// Create a new error (of a given kind) with a formatted message
macro_rules! err {
    ($kind:path, $msg:expr) => {
        crate::error::Error::new($kind, Some($msg.to_string()))
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        err!($kind, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted message
macro_rules! fail {
    ($kind:path, $msg:expr) => {
        return Err(err!($kind, $msg).into());
    };
    ($kind:path, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, &format!($fmt, $($arg)+));
    };
}

/// Assert a condition is true, returning an error type with a formatted message if not
macro_rules! ensure {
    ($cond:expr, $kind:path, $msg:expr) => {
        if !($cond) {
            return Err(err!($kind, $msg).into());
        }
    };
    ($cond:expr, $kind:path, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err(err!($kind, $fmt, $($arg)+).into());
        }
    };
}
