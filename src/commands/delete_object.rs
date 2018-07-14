//! Delete an object of the given ID and type
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>

use super::{Command, Response};
use {CommandType, Connector, ObjectId, ObjectType, Session, SessionError};

/// Delete an object of the given ID and type
pub fn delete_object<C: Connector>(
    session: &mut Session<C>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<(), SessionError> {
    session.send_encrypted_command(DeleteObjectCommand {
        object_id,
        object_type,
    })?;
    Ok(())
}

/// Request parameters for `commands::delete_object`
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

/// Response from `commands::delete_object`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeleteObjectResponse {}

impl Response for DeleteObjectResponse {
    const COMMAND_TYPE: CommandType = CommandType::DeleteObject;
}
