//! Delete an object of the given ID and type
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectId, ObjectType};

/// Delete an object of the given ID and type
pub fn delete_object<A: Adapter>(
    session: &mut Client<A>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<(), ClientError> {
    session.send_command(DeleteObjectCommand {
        object_id,
        object_type,
    })?;
    Ok(())
}

/// Request parameters for `command::delete_object`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeleteObjectCommand {
    /// Object ID to delete
    pub object_id: ObjectId,

    /// Type of object to delete
    pub object_type: ObjectType,
}

impl Command for DeleteObjectCommand {
    type ResponseType = DeleteObjectResponse;
}

/// Response from `command::delete_object`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeleteObjectResponse {}

impl Response for DeleteObjectResponse {
    const COMMAND_TYPE: CommandType = CommandType::DeleteObject;
}
