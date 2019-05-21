//! yubihsm-connector HTTP configuration

use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Default timeouts for reading and writing (5 seconds)
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 5000;

/// Configuration options for the HTTP (i.e. `yubihsm-connector`) connection
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpConfig {
    /// Address of `yubihsm-connector` (IP address or DNS name)
    pub addr: String,

    /// Port `yubihsm-connector` process is listening on
    pub port: u16,

    /// Timeout for connecting, reading, and writing in milliseconds
    pub timeout_ms: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            // Default `yubihsm-connector` address
            addr: "127.0.0.1".to_owned(),

            // Default `yubihsm-connector` port
            port: 12345,

            // 5 seconds
            timeout_ms: DEFAULT_TIMEOUT_MILLIS,
        }
    }
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: HTTPS support
        write!(f, "http://{}:{}", self.addr, self.port)
    }
}
