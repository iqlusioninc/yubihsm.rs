//! Encrypt data (with AES-CCM) using the given wrap key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
    wrap,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrapDataCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: object::Id,

    /// Data to be encrypted/wrapped
    pub plaintext: Vec<u8>,
}

impl Command for WrapDataCommand {
    type ResponseType = WrapDataResponse;
}

/// Response from `command::wrap_data`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrapDataResponse(pub(crate) wrap::Message);

impl Response for WrapDataResponse {
    const COMMAND_CODE: command::Code = command::Code::WrapData;
}
