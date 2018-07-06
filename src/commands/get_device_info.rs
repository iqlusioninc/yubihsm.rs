//! Get information about the YubiHSM2 device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>

use super::{Command, Response};
use {Algorithm, CommandType, Connector, Session, SessionError};

/// Get information about the YubiHSM2 device
pub fn get_device_info<C: Connector>(
    session: &mut Session<C>,
) -> Result<GetDeviceInfoResponse, SessionError> {
    session.send_encrypted_command(GetDeviceInfoCommand {})
}

/// Request parameters for `commands::get_device_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetDeviceInfoCommand {}

impl Command for GetDeviceInfoCommand {
    type ResponseType = GetDeviceInfoResponse;
}

/// Response from `commands::get_device_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDeviceInfoResponse {
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

impl Response for GetDeviceInfoResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetDeviceInfo;
}
