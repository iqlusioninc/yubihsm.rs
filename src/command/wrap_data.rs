//! Encrypt data (with AES-CCM) using the given wrap key
//!
//! https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectId, WrapMessage};

/// Export an encrypted object from the `YubiHSM2` using the given key-wrapping key
pub fn wrap_data<A: Adapter>(
    session: &mut Client<A>,
    wrap_key_id: ObjectId,
    plaintext: Vec<u8>,
) -> Result<WrapMessage, ClientError> {
    session
        .send_command(WrapDataCommand {
            wrap_key_id,
            plaintext,
        }).map(|response| response.0)
}

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
    const COMMAND_TYPE: CommandType = CommandType::WrapData;
}
