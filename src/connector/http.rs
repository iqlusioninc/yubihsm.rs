//! Connection for `yubihsm-connector` which communicates using HTTP.
//!
//! <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>

mod config;
#[cfg(feature = "http")]
mod connection;
#[cfg(feature = "http-server")]
mod server;

pub use self::config::HttpConfig;
#[cfg(feature = "http-server")]
pub use self::server::Server;

#[cfg(feature = "http")]
use self::connection::HttpConnection;
use crate::connector::{self, Connectable, Connection};

/// Connect to the HSM via HTTP(S) using `yubihsm-connector`.
///
/// `HttpConnector` is available when the `http` cargo feature is enabled.
/// The feature is presently enabled-by-default.
///
/// `yubihsm-connector` service is a small HTTP(S) service included in the
/// [Yubico SDK] which exposes an HSM to a network, allowing several clients
/// to use it concurrently.
///
/// For more information on `yubihsm-connector`, see:
///
/// <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>
///
/// [Yubico SDK]: https://developers.yubico.com/YubiHSM2/Releases/
#[derive(Clone, Default, Debug)]
pub(crate) struct HttpConnector(HttpConfig);

impl HttpConnector {
    /// Create a new `HttpConnector` with the given configuration
    pub fn create(config: &HttpConfig) -> Box<dyn Connectable> {
        Box::new(HttpConnector(config.clone()))
    }
}

impl Connectable for HttpConnector {
    /// Make a clone of this connectable as boxed trait object
    fn box_clone(&self) -> Box<dyn Connectable> {
        Box::new(HttpConnector(self.0.clone()))
    }

    /// Open a connection to `yubihsm-connector`
    fn connect(&self) -> Result<Box<dyn Connection>, connector::Error> {
        Ok(Box::new(HttpConnection::open(&self.0)?))
    }
}

impl Into<Box<dyn Connectable>> for HttpConnector {
    fn into(self) -> Box<dyn Connectable> {
        Box::new(self)
    }
}
