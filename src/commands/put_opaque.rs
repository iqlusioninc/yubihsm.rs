//! Put an opaque object into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html>

use super::{Command, PutObjectCommand, Response};
use {
    Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel, OpaqueAlgorithm, Session,
    SessionError,
};

/// Put an opaque object (X.509 certificate or other bytestring) into the `YubiHSM2`
pub fn put_opaque<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    object_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: OpaqueAlgorithm,
    bytes: T,
) -> Result<PutOpaqueResponse, SessionError> {
    session.send_encrypted_command(PutOpaqueCommand(PutObjectCommand {
        id: object_id,
        label,
        domains,
        capabilities,
        algorithm: algorithm.into(),
        data: bytes.into(),
    }))
}

/// Request parameters for `commands::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOpaqueCommand(pub(crate) PutObjectCommand);

impl Command for PutOpaqueCommand {
    type ResponseType = PutOpaqueResponse;
}

/// Response from `commands::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub struct PutOpaqueResponse {
    /// ID of the opaque data object
    pub object_id: ObjectId,
}

impl Response for PutOpaqueResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutOpaqueObject;
}
