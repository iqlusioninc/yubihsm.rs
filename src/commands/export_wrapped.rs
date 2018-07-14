//! Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrap_Key.html>

use super::{Command, Response};
use {CommandType, Connector, ObjectId, ObjectType, Session, SessionError, WrapMessage};

/// Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
pub fn export_wrapped<C: Connector>(
    session: &mut Session<C>,
    wrap_key_id: ObjectId,
    object_type: ObjectType,
    object_id: ObjectId,
) -> Result<WrapMessage, SessionError> {
    session
        .send_encrypted_command(ExportWrappedCommand {
            wrap_key_id,
            object_type,
            object_id,
        })
        .map(|response| response.0)
}

/// Request parameters for `commands::export_wrapped`
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

/// Response from `commands::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedResponse(pub(crate) WrapMessage);

impl Response for ExportWrappedResponse {
    const COMMAND_TYPE: CommandType = CommandType::ExportWrapped;
}
