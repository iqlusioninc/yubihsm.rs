//! Request data for `CommandType::DeleteObject`

use {ObjectId, ObjectType};
use responses::DeleteObjectResponse;
use super::{Command, CommandType};

/// Request data for `CommandType::DeleteObject`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteObjectCommand {
    /// Object ID to delete
    pub object_id: ObjectId,

    /// Type of object to delete
    pub object_type: ObjectType,
}

impl Command for DeleteObjectCommand {
    const COMMAND_TYPE: CommandType = CommandType::DeleteObject;
    type ResponseType = DeleteObjectResponse;
}
