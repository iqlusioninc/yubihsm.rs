//! Import an encrypted object from the `YubiHSM 2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Import_Wrapped.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
    wrap,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportWrappedCommand {
    /// ID of the wrap key to decrypt the object with
    pub wrap_key_id: object::Id,

    /// Nonce used to encrypt the wrapped data
    pub nonce: wrap::Nonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: Vec<u8>,
}

impl Command for ImportWrappedCommand {
    type ResponseType = ImportWrappedResponse;
}

/// Response from `command::import_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ImportWrappedResponse {
    /// Type of object
    pub object_type: object::Type,

    /// ID of the decrypted object
    pub object_id: object::Id,
}

impl Response for ImportWrappedResponse {
    const COMMAND_CODE: command::Code = command::Code::ImportWrapped;
}
