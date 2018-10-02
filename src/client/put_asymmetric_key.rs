//! Put an existing asymmetric key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::put_object::PutObjectParams;
use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

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
    pub key_id: ObjectId,
}

impl Response for PutAsymmetricKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutAsymmetricKey;
}
