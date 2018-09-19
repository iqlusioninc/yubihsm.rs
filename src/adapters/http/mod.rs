//! Minimalist HTTP client designed for use with yubihsm-connector
//!
//! This is not a full-fledged HTTP client and has been specifically designed
//! to work with yubihsm-connector, which uses HTTP as a wrapper for the
//! underlying YubiHSM encrypted channel protocol.
//!
//! We include this client rather than using a standard crate to minimize
//! dependencies/code surface as well as permit potential usage of this crate
//! in environments (e.g. Intel SGX) where it might be difficult to use a
//! full-fledged HTTP crate (e.g. hyper).

#[macro_use]
mod macros;

mod adapter;
mod config;
mod response;
mod status;

use self::response::ResponseReader;
pub use self::{adapter::HttpAdapter, config::HttpConfig, status::ConnectorStatus};

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// Maximum size of the HTTP response from `yubihsm-connector`
pub const MAX_RESPONSE_SIZE: usize = 4096;
