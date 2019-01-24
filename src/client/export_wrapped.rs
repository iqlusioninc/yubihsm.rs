//! Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrapped.html>

use crate::command::{Command, CommandCode};
use crate::object::{ObjectId, ObjectType};
use crate::response::Response;
use crate::wrap::WrapMessage;

/// Request parameters for `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: ObjectId,

    /// Type of object to be wrapped
    pub object_type: ObjectType,

    /// Object ID of the object to be exported (in encrypted form)
    pub object_id: ObjectId,
}

impl Command for ExportWrappedCommand {
    type ResponseType = ExportWrappedResponse;
}

/// Response from `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedResponse(pub(crate) WrapMessage);

impl Response for ExportWrappedResponse {
    const COMMAND_CODE: CommandCode = CommandCode::ExportWrapped;
}
