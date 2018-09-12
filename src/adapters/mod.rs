#[macro_use]
mod error;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "usb")]
pub mod usb;

use std::fmt::Debug;
use uuid::Uuid;

pub use self::error::{AdapterError, AdapterErrorKind};

/// Adapters for communicating with the YubiHSM2
pub trait Adapter: Sized + Send + Sync {
    /// Configuration options for this adapter
    type Config: Debug + Default + Send + Sync;

    /// Open a connection to this adapter
    fn open(config: &Self::Config) -> Result<Self, AdapterError>;

    /// Are we able to send/receive messages to/from the HSM?
    fn healthcheck(&self) -> Result<(), AdapterError>;

    /// Send a command message to the HSM, then read and return the response
    fn send_message(&self, uuid: Uuid, msg: Vec<u8>) -> Result<Vec<u8>, AdapterError>;
}
