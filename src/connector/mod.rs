#[macro_use]
mod error;
mod http_connector;
mod status;

use std::fmt::{Debug, Display};
use uuid::Uuid;

pub use self::error::{ConnectorError, ConnectorErrorKind};
pub use self::http_connector::{HttpConfig, HttpConnector};
pub use self::status::Status;

/// User-Agent string to supply
pub const USER_AGENT: &str = concat!("yubihsm.rs ", env!("CARGO_PKG_VERSION"));

/// API for communicating with a yubihsm-connector
pub trait Connector: Sized + Send + Sync {
    /// Configuration options for this connector
    type Config: Debug + Default + Display;

    /// Open a connection to a yubihsm-connector
    fn open(config: Self::Config) -> Result<Self, ConnectorError>;

    /// Reconnect to yubihsm-connector, closing the existing connection
    fn reconnect(&self) -> Result<(), ConnectorError>;

    /// GET /connector/status returning the result as connector::Status
    fn status(&self) -> Result<Status, ConnectorError>;

    /// POST /connector/api with a given command message and return the response message
    fn send_command(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, ConnectorError>;
}
