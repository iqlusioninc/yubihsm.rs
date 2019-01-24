//! Encrypt data (with AES-CCM) using the given wrap key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html>

use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;
use crate::wrap::WrapMessage;

/// Request parameters for `command::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrapDataCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: ObjectId,

    /// Data to be encrypted/wrapped
    pub plaintext: Vec<u8>,
}

impl Command for WrapDataCommand {
    type ResponseType = WrapDataResponse;
}

/// Response from `command::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrapDataResponse(pub(crate) WrapMessage);

impl Response for WrapDataResponse {
    const COMMAND_CODE: CommandCode = CommandCode::WrapData;
}
