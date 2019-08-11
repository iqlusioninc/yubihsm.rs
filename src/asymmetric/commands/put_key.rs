//! Put an existing asymmetric key into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutAsymmetricKeyCommand {
    type ResponseType = PutAsymmetricKeyResponse;
}

/// Response from `command::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutAsymmetricKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutAsymmetricKey;
}
