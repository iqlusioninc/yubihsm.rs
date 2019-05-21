//! Get the public key for an asymmetric key stored on the device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Public_Key.html>

use crate::{
    asymmetric::PublicKey,
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::get_public_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPublicKeyCommand {
    /// Object ID of the key to obtain the corresponding pubkey for
    pub key_id: object::Id,
}

impl Command for GetPublicKeyCommand {
    type ResponseType = GetPublicKeyResponse;
}

/// Response from `command::get_public_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct GetPublicKeyResponse(pub(crate) PublicKey);

impl Response for GetPublicKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GetPublicKey;
}

impl From<GetPublicKeyResponse> for PublicKey {
    fn from(response: GetPublicKeyResponse) -> PublicKey {
        response.0
    }
}
