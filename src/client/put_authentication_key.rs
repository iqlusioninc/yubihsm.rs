//! Put an existing auth key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authkey.html>

use super::put_object::PutObjectParams;
use crate::authentication_key::AuthenticationKey;
use crate::capability::Capability;
use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;

/// Request parameters for `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyCommand {
    /// Common parameters to all put object command
    pub params: PutObjectParams,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Authentication key
    pub authentication_key: AuthenticationKey,
}

impl Command for PutAuthenticationKeyCommand {
    type ResponseType = PutAuthenticationKeyResponse;
}

/// Response from `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAuthenticationKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutAuthenticationKey;
}
