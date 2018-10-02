use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "mockhsm")]
use serialization::serialize;

mod code;
mod message;

pub use self::code::ResponseCode;
pub(crate) use self::message::ResponseMessage;
use command::CommandCode;

/// Structured responses to `Command` messages sent from the HSM
pub(crate) trait Response: Serialize + DeserializeOwned + Sized {
    /// Command ID this response is for
    const COMMAND_CODE: CommandCode;

    /// Serialize a response type into a ResponseMessage
    #[cfg(feature = "mockhsm")]
    fn serialize(&self) -> ResponseMessage {
        ResponseMessage::success(Self::COMMAND_CODE, serialize(self).unwrap())
    }
}
