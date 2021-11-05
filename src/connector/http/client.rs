//! Minimalist HTTP client
// TODO(tarcieri): replace this with e.g. `ureq`?

#[macro_use]
pub mod error;

pub mod connection;
pub mod path;
pub mod request;
pub mod response;

pub use self::{connection::*, error::*, path::*};

/// HTTP version.
pub const HTTP_VERSION: &str = "HTTP/1.1";

/// `User-Agent` string.
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));
