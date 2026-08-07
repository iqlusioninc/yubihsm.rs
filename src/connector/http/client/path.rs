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

    /// Create a path from the given string.
    ///
    /// The path is interpolated directly into the HTTP request line, so it is
    /// validated here rather than at the point of use: a path containing CR or
    /// LF would let a caller terminate the request line early and inject
    /// arbitrary headers or a second request.
    fn from_str(path: &str) -> Result<Self, Error> {
        if path.is_empty() {
            return Err(err!(ParseError, "empty HTTP path"));
        }

        if !path.starts_with('/') {
            return Err(err!(ParseError, "HTTP path must start with '/': {}", path));
        }

        // Rejects CR and LF (request splitting) along with the other C0
        // controls and DEL, none of which are legal in a request target.
        if let Some(c) = path.chars().find(|c| c.is_ascii_control()) {
            return Err(err!(
                ParseError,
                "HTTP path contains a control character: {:?}",
                c
            ));
        }

        if path.chars().any(|c| c == ' ') {
            return Err(err!(ParseError, "HTTP path contains a space: {}", path));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_paths() {
        for path in ["/", "/connector/api", "/a/b?c=d&e=f", "/%20encoded"] {
            assert!(
                path.parse::<PathBuf>().is_ok(),
                "should have accepted {path:?}"
            );
        }
    }

    #[test]
    fn rejects_request_splitting() {
        // Each of these would otherwise terminate the request line early and
        // inject a header or a second request.
        for path in [
            "/api\r\nX-Injected: 1",
            "/api\nX-Injected: 1",
            "/api\r",
            "/api\n\r\nGET /admin HTTP/1.1",
        ] {
            assert!(
                path.parse::<PathBuf>().is_err(),
                "should have rejected {path:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_paths() {
        for path in ["", "connector/api", "/api with space", "/api\0"] {
            assert!(
                path.parse::<PathBuf>().is_err(),
                "should have rejected {path:?}"
            );
        }
    }

    #[test]
    fn the_path_actually_used_is_accepted() {
        assert_eq!(
            "/connector/api".parse::<PathBuf>().unwrap().as_ref(),
            "/connector/api"
        );
    }
}
