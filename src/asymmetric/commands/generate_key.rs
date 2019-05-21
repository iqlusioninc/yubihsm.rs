//! Generate a new asymmetric key within the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>

use crate::{
    command::{self, Command},
    object::{self, generate},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyCommand(pub(crate) generate::Params);

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Response from `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GenerateAsymmetricKey;
}
