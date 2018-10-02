//! Have the card echo an input message
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>

use command::{Command, CommandCode};
use response::Response;

/// Request parameters for `command::echo`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    type ResponseType = EchoResponse;
}

/// Response from `command::echo`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoResponse(pub(crate) Vec<u8>);

impl Response for EchoResponse {
    const COMMAND_CODE: CommandCode = CommandCode::Echo;
}
