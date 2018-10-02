//! Close the current session and release its resources for reuse
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Close_Session.html>

use command::{Command, CommandCode};
use response::Response;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CloseSessionCommand {}

impl Command for CloseSessionCommand {
    type ResponseType = CloseSessionResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CloseSessionResponse {}

impl Response for CloseSessionResponse {
    const COMMAND_CODE: CommandCode = CommandCode::CloseSession;
}
