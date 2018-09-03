#[macro_use]
mod error;
mod http;
#[cfg(features = "usb")]
mod usb;

use std::fmt::{Debug, Display};
use uuid::Uuid;

pub use self::error::{AdapterError, AdapterErrorKind};
pub use self::http::{HttpAdapter, HttpConfig};

/// Adapters for communicating with the YubiHSM2
pub trait Adapter: Sized + Send + Sync {
    /// Configuration options for this adapter
    type Config: Debug + Default + Display;

    /// Status type for this adapter
    type Status;

    /// Open a connection to a yubihsm-connector
    fn open(config: Self::Config) -> Result<Self, AdapterError>;

    /// Reconnect to yubihsm-connector, closing the existing connection
    fn reconnect(&self) -> Result<(), AdapterError>;

    /// Get the status of this adapter
    fn status(&self) -> Result<Self::Status, AdapterError>;

    /// POST /adapter/api with a given command message and return the response message
    fn send_command(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError>;
}
