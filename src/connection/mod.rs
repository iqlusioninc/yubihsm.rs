#[macro_use]
mod error;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "usb")]
pub mod usb;

use std::fmt::Debug;
use uuid::Uuid;

pub use self::error::{ConnectionError, ConnectionErrorKind};
use serial_number::SerialNumber;

/// Connections to the HSM
pub trait Connection: Sized + Send + Sync {
    /// Configuration options for this connection
    type Config: Debug + Default + Send + Sync;

    /// Open a connection to this connection
    fn open(config: &Self::Config) -> Result<Self, ConnectionError>;

    /// Are we able to send/receive messages to/from the HSM?
    fn healthcheck(&self) -> Result<(), ConnectionError>;

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, ConnectionError>;

    /// Send a command message to the HSM, then read and return the response
    fn send_message(&self, uuid: Uuid, msg: Vec<u8>) -> Result<Vec<u8>, ConnectionError>;
}
