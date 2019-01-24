//! Blink the LED on the `YubiHSM2` for the given number of seconds
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>

use crate::command::{Command, CommandCode};
use crate::response::Response;

/// Request parameters for `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkCommand {
    /// Number of seconds to blink for
    pub num_seconds: u8,
}

impl Command for BlinkCommand {
    type ResponseType = BlinkResponse;
}

/// Response from `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkResponse {}

impl Response for BlinkResponse {
    const COMMAND_CODE: CommandCode = CommandCode::Blink;
}
