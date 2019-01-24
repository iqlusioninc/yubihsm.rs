//! Connection for `yubihsm-connector` which communicates using HTTP.
//!
//! <https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/>

mod config;
mod connection;
mod status;

use std::str;

use self::connection::HttpConnection;
use super::{Connection, ConnectionError, ConnectionErrorKind::ResponseError, Connector};
use crate::serial_number::SerialNumber;

pub use self::{config::HttpConfig, status::ConnectorStatus};

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// Maximum size of the HTTP response from `yubihsm-connector`
pub const MAX_RESPONSE_SIZE: usize = 4096;

/// HTTP resource path for `yubihsm-connector` status
const CONNECTOR_STATUS_PATH: &str = "/connector/status";

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
pub struct HttpConnector(HttpConfig);

impl HttpConnector {
    /// Create a new `HttpConnector` with the given configuration
    pub fn create(config: &HttpConfig) -> Result<Self, ConnectionError> {
        Ok(HttpConnector(config.clone()))
    }

    /// GET `/connector/status` returning `ConnectorStatus`
    pub fn status(&self) -> Result<ConnectorStatus, ConnectionError> {
        let http_response = HttpConnection::open(&self.0)?.get(CONNECTOR_STATUS_PATH)?;
        ConnectorStatus::parse(str::from_utf8(&http_response)?)
    }
}

impl Connector for HttpConnector {
    /// Open a connection to `yubihsm-connector`
    fn connect(&self) -> Result<Box<Connection>, ConnectionError> {
        Ok(Box::new(HttpConnection::open(&self.0)?))
    }

    /// Check that `yubihsm-connector` is available and returning status `OK`
    fn healthcheck(&self) -> Result<(), ConnectionError> {
        let status = self.status()?;

        if status.message == self::status::CONNECTOR_STATUS_OK {
            Ok(())
        } else {
            fail!(
                ResponseError,
                "yubihsm-connector returned unhealthy /connector/status: {}",
                &status.message
            );
        }
    }

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, ConnectionError> {
        self.status()?.serial_number.ok_or_else(|| {
            err!(
                ResponseError,
                "no serial number in yubihsm-connector /connector/status"
            )
        })
    }
}

impl Into<Box<Connector>> for HttpConnector {
    fn into(self) -> Box<Connector> {
        Box::new(self)
    }
}
