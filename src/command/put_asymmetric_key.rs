//! Put an existing asymmetric key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use session::SessionErrorKind::ProtocolError;
use {
    Adapter, AsymmetricAlg, Capability, CommandType, Domain, ObjectId, ObjectLabel, Session,
    SessionError,
};

/// Put an existing asymmetric key into the `YubiHSM2`
pub fn put_asymmetric_key<A: Adapter, T: Into<Vec<u8>>>(
    session: &mut Session<A>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AsymmetricAlg,
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
        .send_command(PutAsymmetricKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            data,
        }).map(|response| response.key_id)
}

/// Request parameters for `command::put_asymmetric_key`
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

/// Response from `command::put_asymmetric_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutAsymmetricKey;
}
