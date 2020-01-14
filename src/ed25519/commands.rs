//! Compute an Ed25519 signature with the given key ID
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html>

use super::Signature;
use crate::{
    client::{self, ErrorKind::ResponseError},
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};
use signature::Signature as _;

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
pub struct SignEddsaResponse(pub(crate) Vec<u8>);

impl Response for SignEddsaResponse {
    const COMMAND_CODE: command::Code = command::Code::SignEddsa;
}

impl SignEddsaResponse {
    pub(crate) fn signature(&self) -> Result<Signature, client::Error> {
        Signature::from_bytes(&self.0).map_err(|e| ResponseError.context(e).into())
    }
}
