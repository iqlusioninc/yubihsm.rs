//! Put an existing wrap key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap_Key.html>

use super::put_object::PutObjectParams;
use capability::Capability;
use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::put_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutWrapKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

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
    pub key_id: ObjectId,
}

impl Response for PutWrapKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutWrapKey;
}
