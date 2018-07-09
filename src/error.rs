pub use failure::{Backtrace, Context, Fail};
use std::error::Error as StdError;
use std::fmt::{self, Display};

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.description {
            Some(ref desc) => write!(f, "{}: {}", &self.inner, desc),
            None => Display::fmt(&self.inner, f),
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
            None => "(no description)",
        }
    }
}
