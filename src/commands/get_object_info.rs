//! Get information about an object
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
//!
use super::{Command, Response};
use {
    CommandType, Connector, ObjectHandle, ObjectId, ObjectInfo, ObjectType, Session, SessionError,
};

/// Get information about an object
pub fn get_object_info<C: Connector>(
    session: &mut Session<C>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<ObjectInfo, SessionError> {
    session
        .send_encrypted_command(GetObjectInfoCommand(ObjectHandle::new(
            object_id,
            object_type,
        )))
        .map(|response| response.0)
}

/// Request parameters for `commands::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoCommand(pub(crate) ObjectHandle);

impl Command for GetObjectInfoCommand {
    type ResponseType = GetObjectInfoResponse;
}

/// Response from `commands::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoResponse(pub(crate) ObjectInfo);

impl Response for GetObjectInfoResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;
}
