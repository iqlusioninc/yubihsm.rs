//! Client for yubihsm-connector

mod error;
#[cfg(feature = "reqwest-connector")]
mod reqwest_connector;
mod status;

use failure::Error;

pub use self::error::ConnectorError;
#[cfg(feature = "reqwest-connector")]
pub use self::reqwest_connector::ReqwestConnector;
pub use self::status::Status;

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// API for communicating with a yubihsm-connector
pub trait Connector: Sized + Send {
    /// Open a connection to a yubihsm-connector
    fn open(connector_url: &str) -> Result<Self, Error>;

    /// GET /connector/status returning the result as connector::Status
    fn status(&self) -> Result<Status, Error>;

    /// POST /connector/api with a given command message and return the response message
    fn send_command(&self, cmd: Vec<u8>) -> Result<Vec<u8>, Error>;
}
