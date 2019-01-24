//! Import an encrypted object from the `YubiHSM2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Import_Wrapped.html>

use crate::command::{Command, CommandCode};
use crate::object::{ObjectId, ObjectType};
use crate::response::Response;
use crate::wrap::WrapNonce;

/// Request parameters for `command::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportWrappedCommand {
    /// ID of the wrap key to decrypt the object with
    pub wrap_key_id: ObjectId,

    /// Nonce used to encrypt the wrapped data
    pub nonce: WrapNonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: Vec<u8>,
}

impl Command for ImportWrappedCommand {
    type ResponseType = ImportWrappedResponse;
}

/// Response from `command::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportWrappedResponse {
    /// Type of object
    pub object_type: ObjectType,

    /// ID of the decrypted object
    pub object_id: ObjectId,
}

impl Response for ImportWrappedResponse {
    const COMMAND_CODE: CommandCode = CommandCode::ImportWrapped;
}
