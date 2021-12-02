//! RSA OAEP commands

use crate::{
    command::{self, Command},
    object,
    response::Response,
    rsa,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::decrypt_rsa_oaep`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DecryptOaepCommand {
    /// ID of the decryption key
    pub key_id: object::Id,

    /// Hash algorithm to use for MGF1
    pub mgf1_hash_alg: rsa::mgf::Algorithm,

    /// Data to be decrypted
    pub data: Vec<u8>,

    /// Hash of the OAEP label
    pub label_hash: Vec<u8>,
}

impl Command for DecryptOaepCommand {
    type ResponseType = DecryptOaepResponse;
}

/// RSA OAEP decrypted data
#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptOaepResponse(rsa::oaep::DecryptedData);

impl Response for DecryptOaepResponse {
    const COMMAND_CODE: command::Code = command::Code::DecryptOaep;
}

impl From<DecryptOaepResponse> for rsa::oaep::DecryptedData {
    fn from(response: DecryptOaepResponse) -> rsa::oaep::DecryptedData {
        response.0
    }
}
