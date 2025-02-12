//! Remote paths on HTTP servers

use super::error::Error;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// Paths to HTTP resources (owned buffer)
// TODO: corresponding borrowed `Path` type
pub struct PathBuf(String);

impl FromStr for PathBuf {
    type Err = Error;

    /// Create a path from the given string
    fn from_str(path: &str) -> Result<Self, Error> {
        // TODO: validate path
        Ok(PathBuf(path.to_owned()))
    }
}

impl AsRef<str> for PathBuf {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for PathBuf {
    fn from(path: &str) -> Self {
        Self::from_str(path).unwrap()
    }
}
