use serde::{de::DeserializeOwned, ser::Serialize};

use crate::response::Response;
use crate::serialization::serialize;

mod code;
mod message;

pub use self::code::CommandCode;
pub(crate) use self::message::CommandMessage;

/// Maximum size of a message sent to/from the YubiHSM
pub const MAX_MSG_SIZE: usize = 2048;

/// Structured command (i.e. requests) which are encrypted and then sent to
/// the HSM. Every command has a corresponding `ResponseType`.
///
/// See <https://developers.yubico.com/YubiHSM2/Commands>
pub(crate) trait Command: Serialize + DeserializeOwned + Sized {
    /// Response type for this command
    type ResponseType: Response;

    /// Command ID for this command
    const COMMAND_CODE: CommandCode = Self::ResponseType::COMMAND_CODE;
}

impl<C: Command> From<C> for CommandMessage {
    fn from(command: C) -> CommandMessage {
        Self::create(C::COMMAND_CODE, serialize(&command).unwrap()).unwrap()
    }
}
