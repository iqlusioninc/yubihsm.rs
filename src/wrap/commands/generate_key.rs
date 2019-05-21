//! Generate a wrapping (i.e. encryption) key within the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Wrap_Key.html>

use crate::{
    capability::Capability,
    command::{self, Command},
    object::{self, generate},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::generate_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenWrapKeyCommand {
    /// Common parameters to all key generation commands
    pub params: generate::Params,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,
}

impl Command for GenWrapKeyCommand {
    type ResponseType = GenWrapKeyResponse;
}

/// Response from `command::generate_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenWrapKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for GenWrapKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GenerateWrapKey;
}
