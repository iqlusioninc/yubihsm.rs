//! Put an existing wrap key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap.html>

use super::{Command, PutObjectCommand, Response};
use {
    Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel, Session, SessionError,
    WrapAlgorithm,
};

/// Put an existing wrap key into the `YubiHSM2`
///
/// Valid algorithms
pub fn put_wrap_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: WrapAlgorithm,
    key_bytes: T,
) -> Result<PutWrapKeyResponse, SessionError> {
    let data = key_bytes.into();

    if data.len() != algorithm.key_len() {
        command_fail!(
            ProtocolError,
            "invalid key length for {:?}: {} (expected {})",
            algorithm,
            data.len(),
            algorithm.key_len()
        );
    }

    session.send_encrypted_command(PutWrapKeyCommand(PutObjectCommand {
        id: key_id,
        label,
        domains,
        capabilities,
        algorithm: algorithm.into(),
        data,
    }))
}

/// Request parameters for `commands::put_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutWrapKeyCommand(pub(crate) PutObjectCommand);

impl Command for PutWrapKeyCommand {
    type ResponseType = PutWrapKeyResponse;
}

/// Response from `commands::put_wrap_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct PutWrapKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutWrapKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutWrapKey;
}
