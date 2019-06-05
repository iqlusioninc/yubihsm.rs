//! Trait shared across all methods for connecting to the YubiHSM2

use crate::connector;
use uuid::Uuid;

/// Connections to the HSM
pub trait Connection: Send + Sync {
    /// Send a command message to the HSM, then read and return the response
    fn send_message(
        &self,
        uuid: Uuid,
        msg: connector::Message,
    ) -> Result<connector::Message, connector::Error>;
}
