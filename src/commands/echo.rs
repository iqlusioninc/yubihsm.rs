//! Request data for `CommandType::Echo`

use responses::EchoResponse;
use super::{Command, CommandType};

/// Request data for `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
    type ResponseType = EchoResponse;
}
