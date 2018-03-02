//! Request data for `CommandType::Echo`

use responses::EchoResponse;
use super::{Command, CommandType};
#[cfg(feature = "mockhsm")]
use super::{CommandMessage, Error};

/// Request data for `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Debug)]
pub struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
    type ResponseType = EchoResponse;

    /// Serialize data
    // TODO: procedurally generate this
    fn into_vec(self) -> Vec<u8> {
        self.message
    }

    /// Deserialize data
    #[cfg(feature = "mockhsm")]
    fn parse(command_msg: CommandMessage) -> Result<Self, Error> {
        Ok(Self {
            message: command_msg.data,
        })
    }
}
