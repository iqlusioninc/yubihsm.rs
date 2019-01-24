//! Put an existing HMAC key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>

use super::put_object::PutObjectParams;
use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;

/// Minimum allowed size of an HMAC key (64-bits)
pub const HMAC_MIN_KEY_SIZE: usize = 8;

/// Request parameters for `command::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHMACKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub hmac_key: Vec<u8>,
}

impl Command for PutHMACKeyCommand {
    type ResponseType = PutHMACKeyResponse;
}

/// Response from `command::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHMACKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutHMACKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutHmacKey;
}
