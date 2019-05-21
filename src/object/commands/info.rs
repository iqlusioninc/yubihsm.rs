//! Get information about an object
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoCommand(pub(crate) object::Handle);

impl Command for GetObjectInfoCommand {
    type ResponseType = GetObjectInfoResponse;
}

/// Response from `command::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoResponse(pub(crate) object::Info);

impl Response for GetObjectInfoResponse {
    const COMMAND_CODE: command::Code = command::Code::GetObjectInfo;
}
