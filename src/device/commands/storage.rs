//! Get storage status (i.e. currently free storage) from the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Storage_Info.html>

use crate::{
    command::{self, Command},
    device::storage,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::get_storage_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetStorageInfoCommand {}

impl Command for GetStorageInfoCommand {
    type ResponseType = GetStorageInfoResponse;
}

/// Response from `command::get_storage_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct GetStorageInfoResponse(pub(crate) storage::Info);

impl Response for GetStorageInfoResponse {
    const COMMAND_CODE: command::Code = command::Code::GetStorageInfo;
}

impl From<GetStorageInfoResponse> for storage::Info {
    fn from(response: GetStorageInfoResponse) -> storage::Info {
        response.0
    }
}
