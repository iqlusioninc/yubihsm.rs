//! Import an encrypted object from the `YubiHSM2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Import_Wrap_Key.html>

use super::{Command, Response};
use {CommandType, Connector, ObjectId, ObjectType, Session, SessionError, WrapNonce, WrappedData};

/// Import an encrypted object from the `YubiHSM2` using the given key-wrapping key
pub fn import_wrapped<C: Connector>(
    session: &mut Session<C>,
    wrap_key_id: ObjectId,
    nonce: WrapNonce,
    ciphertext: WrappedData,
) -> Result<ImportWrappedResponse, SessionError> {
    session.send_encrypted_command(ImportWrappedCommand {
        wrap_key_id,
        nonce,
        ciphertext,
    })
}

/// Request parameters for `commands::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportWrappedCommand {
    /// ID of the wrap key to decrypt the object with
    pub wrap_key_id: ObjectId,

    /// Nonce used to encrypt the wrapped data
    pub nonce: WrapNonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: WrappedData,
}

impl Command for ImportWrappedCommand {
    type ResponseType = ImportWrappedResponse;
}

/// Response from `commands::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportWrappedResponse {
    /// Type of object
    pub object_type: ObjectType,

    /// ID of the decrypted object
    pub object_id: ObjectId,
}

impl Response for ImportWrappedResponse {
    const COMMAND_TYPE: CommandType = CommandType::ImportWrapped;
}
