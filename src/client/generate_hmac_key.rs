//! Generate a new HMAC key within the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Hmac_Key.html>

use super::generate_key::GenerateKeyParams;
use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Request parameters for `command::generate_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenHMACKeyCommand(pub(crate) GenerateKeyParams);

impl Command for GenHMACKeyCommand {
    type ResponseType = GenHMACKeyResponse;
}

/// Response from `command::generate_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenHMACKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for GenHMACKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GenerateHmacKey;
}
