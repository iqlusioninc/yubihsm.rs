//! Put an existing symmetric key into the `YubiHSM 2`
//!
//! <https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#put-symmetric-key-command>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_symmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutSymmetricKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutSymmetricKeyCommand {
    type ResponseType = PutSymmetricKeyResponse;
}

/// Response from `command::put_symmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutSymmetricKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutSymmetricKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutSymmetricKey;
}
