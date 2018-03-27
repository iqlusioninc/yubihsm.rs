//! Client for yubihsm-connector

mod error;
#[cfg(not(feature = "reqwest-connector"))]
mod null_connector;
#[cfg(feature = "reqwest-connector")]
mod reqwest_connector;
mod status;

use failure::Error;

pub use self::error::ConnectorError;
#[cfg(not(feature = "reqwest-connector"))]
pub use self::null_connector::NullConnector;
#[cfg(feature = "reqwest-connector")]
pub use self::reqwest_connector::ReqwestConnector;
pub use self::status::Status;

/// Use `ReqwestConnector` as the default connector if available
#[cfg(feature = "reqwest-connector")]
pub type DefaultConnector = ReqwestConnector;

/// Use NullConnector if the default connector isn't available
#[cfg(not(feature = "reqwest-connector"))]
pub type DefaultConnector = NullConnector;

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
