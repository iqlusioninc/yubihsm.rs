//! Get information about an object
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
//!
use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectHandle, ObjectId, ObjectInfo, ObjectType};

/// Get information about an object
pub fn get_object_info<A: Adapter>(
    session: &mut Client<A>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<ObjectInfo, ClientError> {
    session
        .send_command(GetObjectInfoCommand(ObjectHandle::new(
            object_id,
            object_type,
        ))).map(|response| response.0)
}

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
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;
}
