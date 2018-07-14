//! Put an existing asymmetric key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use {
    AsymmetricAlgorithm, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel,
    Session, SessionError,
};

/// Put an existing asymmetric key into the `YubiHSM2`
pub fn put_asymmetric_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AsymmetricAlgorithm,
    key_bytes: T,
) -> Result<ObjectId, SessionError> {
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

    session
        .send_encrypted_command(PutAsymmetricKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            data,
        })
        .map(|response| response.key_id)
}

/// Request parameters for `commands::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutAsymmetricKeyCommand {
    type ResponseType = PutAsymmetricKeyResponse;
}

/// Response from `commands::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutAsymmetricKey;
}
