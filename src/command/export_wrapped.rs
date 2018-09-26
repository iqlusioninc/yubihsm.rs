//! Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrap_Key.html>

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectId, ObjectType, WrapMessage};

/// Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
pub fn export_wrapped<A: Adapter>(
    session: &mut Client<A>,
    wrap_key_id: ObjectId,
    object_type: ObjectType,
    object_id: ObjectId,
) -> Result<WrapMessage, ClientError> {
    session
        .send_command(ExportWrappedCommand {
            wrap_key_id,
            object_type,
            object_id,
        }).map(|response| response.0)
}

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
    const COMMAND_TYPE: CommandType = CommandType::ExportWrapped;
}
