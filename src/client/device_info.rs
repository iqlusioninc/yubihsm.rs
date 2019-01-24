//! Get information about the `YubiHSM2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Device_Info.html>

use crate::algorithm::Algorithm;
use crate::command::{Command, CommandCode};
use crate::response::Response;

/// Request parameters for `command::device_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeviceInfoCommand {}

impl Command for DeviceInfoCommand {
    type ResponseType = DeviceInfoResponse;
}

/// Response from `command::device_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceInfoResponse {
    /// Device major version
    pub major_version: u8,

    /// Device minor version
    pub minor_version: u8,

    /// Device build version (i.e. patchlevel)
    pub build_version: u8,

    /// Device serial number
    pub serial_number: u32,

    /// Size of the log store (in lines/entries)
    pub log_store_capacity: u8,

    /// Number of log lines used
    pub log_store_used: u8,

    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,
}

impl Response for DeviceInfoResponse {
    const COMMAND_CODE: CommandCode = CommandCode::DeviceInfo;
}
