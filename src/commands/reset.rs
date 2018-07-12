//! Reset the `YubiHSM2` to a factory state, clearing all stored objects,
//! restoring the default auth key, and rebooting
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Reset.html>

use super::{Command, CommandType, Response};
use connector::Connector;
use session::Session;

/// Reset the `YubiHSM2` to a factory default state and reboot
pub fn reset<C: Connector>(mut session: Session<C>) {
    // Resetting the session does not send a valid response
    let _ = session.send_encrypted_command(ResetCommand {});
}

/// Request parameters for `commands::reset`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ResetCommand {}

impl Command for ResetCommand {
    type ResponseType = ResetResponse;
}

/// Response from `commands::reset`
#[derive(Serialize, Deserialize, Debug)]
pub struct ResetResponse(pub(crate) u8);

impl Response for ResetResponse {
    const COMMAND_TYPE: CommandType = CommandType::Reset;
}
