//! Compute an ECDSA signature with the given key ID.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Ecdsa.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Sign ECDSA command parameters
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignEcdsaCommand {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignEcdsaCommand {
    type ResponseType = SignEcdsaResponse;
}

/// Response from ECDSA signing request
#[derive(Serialize, Deserialize, Debug)]
pub struct SignEcdsaResponse(pub Vec<u8>);

impl Response for SignEcdsaResponse {
    const COMMAND_CODE: command::Code = command::Code::SignEcdsa;
}

impl From<SignEcdsaResponse> for Vec<u8> {
    fn from(response: SignEcdsaResponse) -> Vec<u8> {
        response.0
    }
}
