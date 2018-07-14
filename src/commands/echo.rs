//! Have the card echo an input message
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>

use super::{Command, Response};
use {CommandType, Connector, Session, SessionError};

/// Have the card echo an input message
pub fn echo<C, T>(session: &mut Session<C>, message: T) -> Result<Vec<u8>, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session
        .send_encrypted_command(EchoCommand {
            message: message.into(),
        })
        .map(|response| response.0)
}

/// Request parameters for `commands::echo`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    type ResponseType = EchoResponse;
}

/// Response from `commands::ccho`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoResponse(pub(crate) Vec<u8>);

impl Response for EchoResponse {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
}
