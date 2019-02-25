//! Responses to command sent from the HSM.

mod code;
mod message;

pub use self::code::Code;
pub(crate) use self::message::Message;
use crate::command;
#[cfg(feature = "mockhsm")]
use crate::serialization::serialize;
use serde::{de::DeserializeOwned, Serialize};

/// Structured responses to `Command` messages sent from the HSM
pub(crate) trait Response: Serialize + DeserializeOwned + Sized {
    /// Command ID this response is for
    const COMMAND_CODE: command::Code;

    /// Serialize a response type into a response::Message
    #[cfg(feature = "mockhsm")]
    fn serialize(&self) -> Message {
        Message::success(Self::COMMAND_CODE, serialize(self).unwrap())
    }
}
