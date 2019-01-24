//! Delete an object of the given ID and type
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>

use crate::command::{Command, CommandCode};
use crate::object::{ObjectId, ObjectType};
use crate::response::Response;

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
    const COMMAND_CODE: CommandCode = CommandCode::DeleteObject;
}
