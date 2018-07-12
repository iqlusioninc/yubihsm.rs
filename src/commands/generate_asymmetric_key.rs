//! Generate a new asymmetric key within the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>

use super::generate_key::GenerateKeyParams;
use super::{Command, Response};
use {
    AsymmetricAlgorithm, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel,
    Session, SessionError,
};

/// Generate a new asymmetric key within the `YubiHSM2`
pub fn generate_asymmetric_key<C: Connector>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AsymmetricAlgorithm,
) -> Result<ObjectId, SessionError> {
    session
        .send_encrypted_command(GenAsymmetricKeyCommand(GenerateKeyParams {
            key_id,
            label,
            domains,
            capabilities,
            algorithm: algorithm.into(),
        }))
        .map(|response| response.key_id)
}

/// Request parameters for `commands::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyCommand(pub(crate) GenerateKeyParams);

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Response from `commands::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GenerateAsymmetricKey;
}
