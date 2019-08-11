//! Put an existing auth key into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authentication_Key.html>

use crate::{
    authentication,
    capability::Capability,
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyCommand {
    /// Common parameters to all put object command
    pub params: object::put::Params,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Authentication key
    pub authentication_key: authentication::Key,
}

impl Command for PutAuthenticationKeyCommand {
    type ResponseType = PutAuthenticationKeyResponse;
}

/// Response from `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutAuthenticationKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutAuthenticationKey;
}
