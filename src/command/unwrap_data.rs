//! Decrypt data which was encrypted (using AES-CCM) under a wrap key
//!
//! https://developers.yubico.com/YubiHSM2/Commands/Unwrap_Data.html

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectId, WrapMessage, WrapNonce};

/// Decrypt data which was encrypted (using AES-CCM) under a wrap key
pub fn unwrap_data<A, M>(
    session: &mut Client<A>,
    wrap_key_id: ObjectId,
    wrap_message: M,
) -> Result<Vec<u8>, ClientError>
where
    A: Adapter,
    M: Into<WrapMessage>,
{
    let WrapMessage { nonce, ciphertext } = wrap_message.into();

    session
        .send_command(UnwrapDataCommand {
            wrap_key_id,
            nonce,
            ciphertext,
        }).map(|response| response.0)
}

/// Request parameters for `command::unwrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UnwrapDataCommand {
    /// ID of the wrap key to decrypt the object with
    pub wrap_key_id: ObjectId,

    /// Nonce used to encrypt the wrapped data
    pub nonce: WrapNonce,

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
    const COMMAND_TYPE: CommandType = CommandType::UnwrapData;
}
