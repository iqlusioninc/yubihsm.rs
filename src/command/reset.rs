//! Reset the device: clear all stored objects, restore the default auth key,
//! and reboot
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Reset.html>

use super::{Command, CommandType, Response};
use client::{Client, ClientError, ClientErrorKind};
use connection::Connection;

/// Reset the `YubiHSM2` to a factory default state and reboot
pub fn reset<A: Connection>(mut session: Client<A>) -> Result<(), ClientError> {
    // Resetting the session does not send a valid response
    if let Err(e) = session.send_command(ResetCommand {}) {
        match e.kind() {
            // TODO: we don't handle the yubihsm-connector response to reset correctly
            ClientErrorKind::ProtocolError => Ok(()),
            _ => Err(e),
        }
    } else {
        Ok(())
    }
}

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
    const COMMAND_TYPE: CommandType = CommandType::Reset;
}
