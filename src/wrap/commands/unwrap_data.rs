//! Decrypt data which was encrypted (using AES-CCM) under a wrap key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Unwrap_Data.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
    wrap,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::unwrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UnwrapDataCommand {
    /// ID of the wrap key to decrypt the object with
    pub wrap_key_id: object::Id,

    /// Nonce used to encrypt the wrapped data
    pub nonce: wrap::Nonce,

    /// Ciphertext of the encrypted data (including MAC)
    pub ciphertext: Vec<u8>,
}

impl Command for UnwrapDataCommand {
    type ResponseType = UnwrapDataResponse;
}

/// Response from `command::unwrap_data` containing decrypted plaintext
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UnwrapDataResponse(pub(crate) Vec<u8>);

impl Response for UnwrapDataResponse {
    const COMMAND_CODE: command::Code = command::Code::UnwrapData;
}
