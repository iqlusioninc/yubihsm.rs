//! Put an existing wrap key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use session::SessionErrorKind::ProtocolError;
use {
    Adapter, Capability, CommandType, Domain, ObjectId, ObjectLabel, Session, SessionError, WrapAlg,
};

/// Put an existing wrap key into the `YubiHSM2`
// TODO: use clippy's scoped lints once they work on stable
#[allow(unknown_lints, renamed_and_removed_lints, too_many_arguments)]
pub fn put_wrap_key<A: Adapter, T: Into<Vec<u8>>>(
    session: &mut Session<A>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    delegated_capabilities: Capability,
    algorithm: WrapAlg,
    key_bytes: T,
) -> Result<ObjectId, SessionError> {
    let data = key_bytes.into();

    if data.len() != algorithm.key_len() {
        fail!(
            ProtocolError,
            "invalid key length for {:?}: {} (expected {})",
            algorithm,
            data.len(),
            algorithm.key_len()
        );
    }

    session
        .send_command(PutWrapKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            delegated_capabilities,
            data,
        }).map(|response| response.key_id)
}

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
    const COMMAND_TYPE: CommandType = CommandType::PutWrapKey;
}
