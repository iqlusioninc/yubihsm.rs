//! Generate a new asymmetric key within the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>

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
) -> Result<GenAsymmetricKeyResponse, SessionError> {
    session.send_encrypted_command(GenAsymmetricKeyCommand {
        key_id,
        label,
        domains,
        capabilities,
        algorithm,
    })
}

/// Request parameters for `commands::generate_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenAsymmetricKeyCommand {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domain in which the key will be accessible
    pub domains: Domain,

    /// Capability of the key
    pub capabilities: Capability,

    /// Key algorithm
    pub algorithm: AsymmetricAlgorithm,
}

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Response from `commands::generate_assymetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GenAsymmetricKey;
}
