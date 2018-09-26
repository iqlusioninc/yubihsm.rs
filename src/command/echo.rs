//! Have the card echo an input message
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType};

/// Have the card echo an input message
pub fn echo<A, T>(session: &mut Client<A>, message: T) -> Result<Vec<u8>, ClientError>
where
    A: Adapter,
    T: Into<Vec<u8>>,
{
    session
        .send_command(EchoCommand {
            message: message.into(),
        }).map(|response| response.0)
}

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
    const COMMAND_TYPE: CommandType = CommandType::Echo;
}
