//! Get storage information about the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Storage_Info.html>

use crate::{
    command::{self, Command},
    device,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::device_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeviceInfoCommand {}

impl Command for DeviceInfoCommand {
    type ResponseType = DeviceInfoResponse;
}

/// Response from `command::device_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceInfoResponse(pub(crate) device::Info);

impl Response for DeviceInfoResponse {
    const COMMAND_CODE: command::Code = command::Code::DeviceInfo;
}

impl From<DeviceInfoResponse> for device::Info {
    fn from(response: DeviceInfoResponse) -> device::Info {
        response.0
    }
}
