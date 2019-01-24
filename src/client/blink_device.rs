//! Blink the LED on the `YubiHSM2` for the given number of seconds
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>

use crate::command::{Command, CommandCode};
use crate::response::Response;

/// Request parameters for `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkDeviceCommand {
    /// Number of seconds to blink for
    pub num_seconds: u8,
}

impl Command for BlinkDeviceCommand {
    type ResponseType = BlinkDeviceResponse;
}

/// Response from `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkDeviceResponse {}

impl Response for BlinkDeviceResponse {
    const COMMAND_CODE: CommandCode = CommandCode::BlinkDevice;
}
