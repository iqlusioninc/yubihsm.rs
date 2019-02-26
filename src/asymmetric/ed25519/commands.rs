//! Compute an Ed25519 signature with the given key ID
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html>

use super::Signature;
use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Request parameters for `command::sign_ed25519`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignEddsaCommand {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Data to be signed
    pub data: Vec<u8>,
}

impl Command for SignEddsaCommand {
    type ResponseType = SignEddsaResponse;
}

/// Ed25519 signature (64-bytes) response
#[derive(Serialize, Deserialize, Debug)]
pub struct SignEddsaResponse(pub(crate) Signature);

impl Response for SignEddsaResponse {
    const COMMAND_CODE: command::Code = command::Code::SignEddsa;
}

impl From<SignEddsaResponse> for Signature {
    fn from(response: SignEddsaResponse) -> Signature {
        response.0
    }
}
