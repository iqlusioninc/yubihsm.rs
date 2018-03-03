//! Request data for `CommandType::GenAsymmetricKey`

use {Algorithm, Capabilities, Domains, ObjectId, ObjectLabel};
use responses::GenAsymmetricKeyResponse;
use super::{Command, CommandType};

/// Request data for `CommandType::GenAsymmetricKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GenAsymmetricKeyCommand {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domains in which the key will be accessible
    pub domains: Domains,

    /// Capabilities of the key
    pub capabilities: Capabilities,

    /// Key algorithm
    pub algorithm: Algorithm,
}

impl Command for GenAsymmetricKeyCommand {
    const COMMAND_TYPE: CommandType = CommandType::GenAsymmetricKey;
    type ResponseType = GenAsymmetricKeyResponse;
}
