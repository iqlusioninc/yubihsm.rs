//! Encrypt data (with AES-CCM) using the given wrap key
//!
//! https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html

use super::{Command, Response};
use {CommandType, Connector, ObjectId, Session, SessionError, WrapNonce, WrappedData};

/// Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
pub fn wrap_data<C: Connector>(
    session: &mut Session<C>,
    wrap_key_id: ObjectId,
    plaintext: Vec<u8>,
) -> Result<WrapDataResponse, SessionError> {
    session.send_encrypted_command(WrapDataCommand {
        wrap_key_id,
        plaintext,
    })
}

/// Request parameters for `commands::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrapDataCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: ObjectId,

    /// Data to be encrypted/wrapped
    pub plaintext: Vec<u8>,
}

impl Command for WrapDataCommand {
    type ResponseType = WrapDataResponse;
}

/// Response from `commands::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub struct WrapDataResponse {
    /// Nonce used to encrypt the wrapped data
    pub nonce: WrapNonce,

    /// "Wrapped" data encrypted with AES-CCM (including MAC)
    pub ciphertext: WrappedData,
}

impl Response for WrapDataResponse {
    const COMMAND_TYPE: CommandType = CommandType::WrapData;
}
