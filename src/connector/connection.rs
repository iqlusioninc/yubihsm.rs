//! Trait shared across all methods for connecting to the YubiHSM2

use super::{error::ConnectionError, message::Message};
use uuid::Uuid;

/// Connections to the HSM
pub trait Connection: Send + Sync {
    /// Send a command message to the HSM, then read and return the response
    fn send_message(&self, uuid: Uuid, msg: Message) -> Result<Message, ConnectionError>;
}
