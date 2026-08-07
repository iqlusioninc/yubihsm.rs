//! CBC related encryption commands

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Encrypt AES CBC command parameters
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EncryptAesCbc {
    /// ID of the key to perform the decryption with
    pub key_id: object::Id,

    /// Payload to be encrypted, IV then payload
    pub payload: Zeroizing<Vec<u8>>,
}

impl Command for EncryptAesCbc {
    type ResponseType = EncryptAesCbcResponse;
}

/// Response from the AES-CBC encryption
#[derive(Serialize, Deserialize)]
pub struct EncryptAesCbcResponse(pub Vec<u8>);

impl Response for EncryptAesCbcResponse {
    const COMMAND_CODE: command::Code = command::Code::EncryptAesCbc;
}

/// Decrypt AES CBC command parameters
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DecryptAesCbc {
    /// ID of the key to perform the decryption with
    pub key_id: object::Id,

    /// Payload to be decrypted, IV then payload
    pub payload: Zeroizing<Vec<u8>>,
}

impl Command for DecryptAesCbc {
    type ResponseType = DecryptAesCbcResponse;
}

/// Response from the AES-CBC decryption
#[derive(Serialize, Deserialize)]
pub struct DecryptAesCbcResponse(pub Vec<u8>);

impl Response for DecryptAesCbcResponse {
    const COMMAND_CODE: command::Code = command::Code::DecryptAesCbc;
}
