//! Get information about an object
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>

use crate::command::{Command, CommandCode};
use crate::object::{ObjectHandle, ObjectInfo};
use crate::response::Response;

/// Request parameters for `command::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoCommand(pub(crate) ObjectHandle);

impl Command for GetObjectInfoCommand {
    type ResponseType = GetObjectInfoResponse;
}

/// Response from `command::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoResponse(pub(crate) ObjectInfo);

impl Response for GetObjectInfoResponse {
    const COMMAND_CODE: CommandCode = CommandCode::GetObjectInfo;
}
