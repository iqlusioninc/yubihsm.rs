//! Generate a new symmetric key within the `YubiHSM 2`
//!
//! <https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#generate-symmetric-key-command>

use crate::{
    command::{self, Command},
    object::{self, generate},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::generate_symmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenSymmetricKeyCommand(pub(crate) generate::Params);

impl Command for GenSymmetricKeyCommand {
    type ResponseType = GenSymmetricKeyResponse;
}

/// Response from `command::generate_symmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenSymmetricKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for GenSymmetricKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GenerateSymmetricKey;
}
