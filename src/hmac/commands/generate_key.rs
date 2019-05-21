//! Generate a new HMAC key within the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Hmac_Key.html>

use crate::{
    command::{self, Command},
    object::{self, generate},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::generate_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenHmacKeyCommand(pub(crate) generate::Params);

impl Command for GenHmacKeyCommand {
    type ResponseType = GenHmacKeyResponse;
}

/// Response from `command::generate_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenHmacKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for GenHmacKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GenerateHmacKey;
}
