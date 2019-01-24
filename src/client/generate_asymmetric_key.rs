//! Generate a new asymmetric key within the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>

use super::generate_key::GenerateKeyParams;
use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;

/// Request parameters for `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyCommand(pub(crate) GenerateKeyParams);

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Response from `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::GenerateAsymmetricKey;
}
