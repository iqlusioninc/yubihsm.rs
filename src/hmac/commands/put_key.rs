//! Put an existing HMAC key into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Minimum allowed size of an HMAC key (64-bits)
pub const HMAC_MIN_KEY_SIZE: usize = 8;

/// Request parameters for `command::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHmacKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Serialized object
    pub hmac_key: Vec<u8>,
}

impl Command for PutHmacKeyCommand {
    type ResponseType = PutHmacKeyResponse;
}

/// Response from `command::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHmacKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutHmacKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutHmacKey;
}
