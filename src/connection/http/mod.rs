//! Connection for `yubihsm-connector` which communicates using HTTP.
//!
//! <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>

#[macro_use]
mod macros;

mod config;
mod connection;
mod response;
mod status;

use self::response::ResponseReader;
pub use self::{config::HttpConfig, connection::HttpConnection, status::ConnectorStatus};

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// Maximum size of the HTTP response from `yubihsm-connector`
pub const MAX_RESPONSE_SIZE: usize = 4096;
