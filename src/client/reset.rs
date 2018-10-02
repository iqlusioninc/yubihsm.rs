//! Reset the device: clear all stored objects, restore the default auth key,
//! and reboot
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Reset.html>

use command::{Command, CommandCode};
use response::Response;

/// Request parameters for `command::reset`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ResetCommand {}

impl Command for ResetCommand {
    type ResponseType = ResetResponse;
}

/// Response from `command::reset`
#[derive(Serialize, Deserialize, Debug)]
pub struct ResetResponse(pub(crate) u8);

impl Response for ResetResponse {
    const COMMAND_CODE: CommandCode = CommandCode::Reset;
}
