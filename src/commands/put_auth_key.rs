//! Put an existing auth key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authkey.html>

use super::{Command, PutObjectCommand, Response};
use {
    AuthAlgorithm, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel, Session,
    SessionError,
};

/// Auth keys are 2 x AES-128 keys (32-bytes)
pub const AUTH_KEY_SIZE: usize = 32;

/// Put an existing auth key into the `YubiHSM2`
pub fn put_auth_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: AuthAlgorithm,
    key_bytes: T,
) -> Result<PutAuthKeyResponse, SessionError> {
    let data = key_bytes.into();

    if data.len() != AUTH_KEY_SIZE {
        command_fail!(
            ProtocolError,
            "invalid key length for auth key: {} (expected {})",
            data.len(),
            AUTH_KEY_SIZE
        );
    }

    session.send_encrypted_command(PutAuthKeyCommand(PutObjectCommand {
        id: key_id,
        label,
        domains,
        capabilities,
        algorithm: algorithm.into(),
        data,
    }))
}

/// Request parameters for `commands::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthKeyCommand(pub(crate) PutObjectCommand);

impl Command for PutAuthKeyCommand {
    type ResponseType = PutAuthKeyResponse;
}

/// Response from `commands::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct PutAuthKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAuthKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutAuthKey;
}
