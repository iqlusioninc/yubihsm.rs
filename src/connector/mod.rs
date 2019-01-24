#[macro_use]
mod error;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "usb")]
pub mod usb;

use uuid::Uuid;

pub use self::error::{ConnectionError, ConnectionErrorKind};
use crate::serial_number::SerialNumber;

/// Connectors which create `Connection` objects to the HSM
pub trait Connector: Send + Sync {
    /// Open a connection to the HSM using this `Connector`
    fn connect(&self) -> Result<Box<Connection>, ConnectionError>;

    /// Ensure the connection to the HSM is healthy, or return an error
    fn healthcheck(&self) -> Result<(), ConnectionError>;

    /// Get the serial number for the HSM (if available)
    fn serial_number(&self) -> Result<SerialNumber, ConnectionError>;
}

/// Connections to the HSM
pub trait Connection: Send + Sync {
    /// Send a command message to the HSM, then read and return the response
    fn send_message(&self, uuid: Uuid, msg: Vec<u8>) -> Result<Vec<u8>, ConnectionError>;
}
