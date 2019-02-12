//! Reset the device: clear all stored objects, restore the default auth key,
//! and reboot
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html>

use crate::command::{Command, CommandCode};
use crate::response::Response;

/// Request parameters for `command::reset_device`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ResetDeviceCommand {}

impl Command for ResetDeviceCommand {
    type ResponseType = ResetDeviceResponse;
}

/// Response from `command::reset_device`
#[derive(Serialize, Deserialize, Debug)]
pub struct ResetDeviceResponse(pub(crate) u8);

impl Response for ResetDeviceResponse {
    const COMMAND_CODE: CommandCode = CommandCode::ResetDevice;
}
