//! Put an opaque object into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html>

use super::put_object::PutObjectParams;
use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;

/// Request parameters for `command::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOpaqueCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutOpaqueCommand {
    type ResponseType = PutOpaqueResponse;
}

/// Response from `command::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOpaqueResponse {
    /// ID of the opaque data object
    pub object_id: ObjectId,
}

impl Response for PutOpaqueResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutOpaqueObject;
}
