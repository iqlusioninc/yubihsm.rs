//! Put an existing auth key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authkey.html>

use super::put_object::PutObjectParams;
use auth_key::AuthKey;
use capability::Capability;
use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthKeyCommand {
    /// Common parameters to all put object command
    pub params: PutObjectParams,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Authentication key
    pub auth_key: AuthKey,
}

impl Command for PutAuthKeyCommand {
    type ResponseType = PutAuthKeyResponse;
}

/// Response from `command::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAuthKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutAuthKey;
}
