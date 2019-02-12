//! Get storage status (i.e. currently free storage) from the `YubiHSM2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Storage_Info.html>

use crate::command::{Command, CommandCode};
use crate::response::Response;

/// Request parameters for `command::get_storage_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetStorageInfoCommand {}

impl Command for GetStorageInfoCommand {
    type ResponseType = GetStorageInfoResponse;
}

/// Response from `command::get_storage_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct GetStorageInfoResponse {
    /// Total number of storage records
    pub total_records: u16,

    /// Storage records which are currently free
    pub free_records: u16,

    /// Total number of storage pages
    pub total_pages: u16,

    /// Storage pages which are currently free
    pub free_pages: u16,

    /// Page size in bytes
    pub page_size: u16,
}

impl Response for GetStorageInfoResponse {
    const COMMAND_CODE: CommandCode = CommandCode::GetStorageInfo;
}
