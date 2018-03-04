//! Request data for `CommandType::GetObjectInfo`

use {ObjectId, ObjectType};
use responses::GetObjectInfoResponse;
use super::{Command, CommandType};

/// Command to delete an object
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetObjectInfoCommand {
    /// Object ID to obtain information about
    pub object_id: ObjectId,

    /// Type of object to obtain information about
    pub object_type: ObjectType,
}

impl Command for GetObjectInfoCommand {
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;
    type ResponseType = GetObjectInfoResponse;
}
