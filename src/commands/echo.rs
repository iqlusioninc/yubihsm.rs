//! Have the card echo an input message
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>

use super::{Command, Response};
use {Adapter, CommandType, Session, SessionError};

/// Have the card echo an input message
pub fn echo<A, T>(session: &mut Session<A>, message: T) -> Result<Vec<u8>, SessionError>
where
    A: Adapter,
    T: Into<Vec<u8>>,
{
    session
        .send_command(EchoCommand {
            message: message.into(),
        }).map(|response| response.0)
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
