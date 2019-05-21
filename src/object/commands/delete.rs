//! Delete an object of the given ID and type
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::delete_object`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeleteObjectCommand {
    /// Object ID to delete
    pub object_id: object::Id,

    /// Type of object to delete
    pub object_type: object::Type,
}

impl Command for DeleteObjectCommand {
    type ResponseType = DeleteObjectResponse;
}

/// Response from `command::delete_object`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeleteObjectResponse {}

impl Response for DeleteObjectResponse {
    const COMMAND_CODE: command::Code = command::Code::DeleteObject;
}
