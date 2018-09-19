//! Generate a new asymmetric key within the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>

use super::generate_key::GenerateKeyParams;
use super::{Command, Response};
use {
    Adapter, AsymmetricAlg, Capability, CommandType, Domain, ObjectId, ObjectLabel, Session,
    SessionError,
};

/// Generate a new asymmetric key within the `YubiHSM2`
pub fn generate_asymmetric_key<A: Adapter>(
    session: &mut Session<A>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AsymmetricAlg,
) -> Result<ObjectId, SessionError> {
    session
        .send_command(GenAsymmetricKeyCommand(GenerateKeyParams {
            key_id,
            label,
            domains,
            capabilities,
            algorithm: algorithm.into(),
        })).map(|response| response.key_id)
}

/// Request parameters for `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyCommand(pub(crate) GenerateKeyParams);

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Response from `command::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GenerateAsymmetricKey;
}
