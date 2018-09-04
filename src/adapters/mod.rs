#[macro_use]
mod error;
pub mod http;
#[cfg(feature = "usb")]
pub mod usb;

use std::fmt::{Debug, Display};
use uuid::Uuid;

pub use self::error::{AdapterError, AdapterErrorKind};

/// Adapters for communicating with the YubiHSM2
pub trait Adapter: Sized + Send + Sync {
    /// Configuration options for this adapter
    type Config: Debug + Default + Display;

    /// Status type for this adapter
    type Status;

    /// Open a connection to this adapter
    fn open(config: Self::Config) -> Result<Self, AdapterError>;

    /// Reconnect to the adapter, terminating the existing connection
    fn reconnect(&self) -> Result<(), AdapterError>;

    /// Get the status of this adapter
    fn status(&self) -> Result<Self::Status, AdapterError>;

    /// Send a command to the YubiHSM, returning the response
    fn send_command(&self, uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError>;
}
