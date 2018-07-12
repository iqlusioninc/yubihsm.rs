//! Put an opaque object into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
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
) -> Result<ObjectId, SessionError> {
    session
        .send_encrypted_command(PutOpaqueCommand {
            params: PutObjectParams {
                id: object_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            data: bytes.into(),
        })
        .map(|response| response.object_id)
}

/// Request parameters for `commands::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOpaqueCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutOpaqueCommand {
    type ResponseType = PutOpaqueResponse;
}

/// Response from `commands::put_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOpaqueResponse {
    /// ID of the opaque data object
    pub object_id: ObjectId,
}

impl Response for PutOpaqueResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutOpaqueObject;
}
