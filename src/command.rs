//! YubiHSM commands: types and traits for modeling the commands supported
//! by the HSM device, implemented in relevant modules.

mod code;
mod error;
mod message;

pub use self::{
    code::Code,
    error::{Error, ErrorKind},
};

pub(crate) use self::message::Message;
use crate::{response::Response, serialization::serialize};
use serde::{de::DeserializeOwned, ser::Serialize};

/// Maximum size of a message sent to/from the YubiHSM
pub const MAX_MSG_SIZE: usize = 2048;

/// Structured command (i.e. requests) which are encrypted and then sent to
/// the HSM. Every command has a corresponding `ResponseType`.
///
/// See <https://developers.yubico.com/YubiHSM2/Commands>
// TODO(tarcieri): add a `Zeroize` bound to clear sensitive data
pub(crate) trait Command: Serialize + DeserializeOwned + Sized {
    /// Response type for this command
    type ResponseType: Response;

    /// Command ID for this command
    const COMMAND_CODE: Code = Self::ResponseType::COMMAND_CODE;
}

impl<'c, C: Command> From<&'c C> for Message {
    fn from(command: &C) -> Message {
        Self::create(C::COMMAND_CODE, serialize(command).unwrap()).unwrap()
    }
}
