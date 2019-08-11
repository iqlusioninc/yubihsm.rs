//! Put an existing wrap key into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap_Key.html>

use crate::{
    capability::Capability,
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutWrapKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutWrapKeyCommand {
    type ResponseType = PutWrapKeyResponse;
}

/// Response from `command::put_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutWrapKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutWrapKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutWrapKey;
}
