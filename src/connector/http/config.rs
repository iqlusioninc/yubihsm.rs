//! yubihsm-connector HTTP configuration

use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
#[cfg(feature = "_tls")]
use std::path::PathBuf;

/// Default timeouts for reading and writing (5 seconds)
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 5000;

/// Configuration options for the HTTP (i.e. `yubihsm-connector`) connection
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpConfig {
    /// Address of `yubihsm-connector` (IP address or DNS name)
    pub addr: String,

    /// Port `yubihsm-connector` process is listening on
    pub port: u16,

    /// Use https if true
    #[cfg(feature = "_tls")]
    #[serde(default)]
    pub tls: bool,

    /// CA certificate to validate the server certificate
    #[cfg(feature = "_tls")]
    #[serde(default)]
    pub cacert: Option<PathBuf>,

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

            #[cfg(feature = "_tls")]
            tls: false,

            #[cfg(feature = "_tls")]
            cacert: None,

            // 5 seconds
            timeout_ms: DEFAULT_TIMEOUT_MILLIS,
        }
    }
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "_tls")]
        if self.tls {
            write!(f, "https://{}:{}", self.addr, self.port)
        } else {
            write!(f, "http://{}:{}", self.addr, self.port)
        }

        #[cfg(not(feature = "_tls"))]
        write!(f, "http://{}:{}", self.addr, self.port)
    }
}

#[cfg(all(test, feature = "setup"))]
mod tests {
    use super::HttpConfig;

    /// A config predating the `https` feature must still deserialize: the new
    /// TLS fields are optional and fall back to plain HTTP.
    #[test]
    fn deserializes_config_without_tls_fields() {
        let config: HttpConfig =
            serde_json::from_str(r#"{"addr":"127.0.0.1","port":12345,"timeout_ms":5000}"#).unwrap();

        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 12345);

        #[cfg(feature = "_tls")]
        {
            assert!(!config.tls);
            assert!(config.cacert.is_none());
        }
    }
}
