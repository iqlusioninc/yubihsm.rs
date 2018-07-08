//! Put an existing asymmetric key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::{Command, PutObjectCommand, Response};
use {
    AsymmetricAlgorithm, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel,
    Session, SessionError,
};

/// Put an existing asymmetric key into the `YubiHSM2`
///
/// Valid algorithms
pub fn put_asymmetric_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AsymmetricAlgorithm,
    key_bytes: T,
) -> Result<PutAsymmetricKeyResponse, SessionError> {
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

    session.send_encrypted_command(PutAsymmetricKeyCommand(PutObjectCommand {
        id: key_id,
        label,
        domains,
        capabilities,
        algorithm: algorithm.into(),
        data,
    }))
}

/// Request parameters for `commands::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyCommand(pub(crate) PutObjectCommand);

impl Command for PutAsymmetricKeyCommand {
    type ResponseType = PutAsymmetricKeyResponse;
}

/// Response from `commands::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct PutAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutAsymmetricKey;
}
