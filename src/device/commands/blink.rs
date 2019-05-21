//! Blink the LED on the `YubiHSM 2` for the given number of seconds
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink_Device.html>

use crate::{
    command::{self, Command},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::blink_device`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkDeviceCommand {
    /// Number of seconds to blink for
    pub num_seconds: u8,
}

impl Command for BlinkDeviceCommand {
    type ResponseType = BlinkDeviceResponse;
}

/// Response from `command::blink_device`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkDeviceResponse {}

impl Response for BlinkDeviceResponse {
    const COMMAND_CODE: command::Code = command::Code::BlinkDevice;
}
