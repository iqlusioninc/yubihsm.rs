//! Put an existing HMAC key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>

use super::{Command, PutObjectCommand, Response};
use {
    Capability, CommandType, Connector, Domain, HMACAlgorithm, ObjectId, ObjectLabel, Session,
    SessionError,
};

/// Minimum allowed size of an HMAC key (64-bits)
pub const HMAC_MIN_KEY_SIZE: usize = 8;

/// Put an existing auth key into the `YubiHSM2`
pub fn put_hmac_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: HMACAlgorithm,
    key_bytes: T,
) -> Result<PutHMACKeyResponse, SessionError> {
    let data = key_bytes.into();

    if data.len() < HMAC_MIN_KEY_SIZE || data.len() > algorithm.max_key_len() {
        command_fail!(
            ProtocolError,
            "invalid key length for {:?}: {} (min {}, max {})",
            algorithm,
            data.len(),
            HMAC_MIN_KEY_SIZE,
            algorithm.max_key_len()
        );
    }

    session.send_encrypted_command(PutHMACKeyCommand(PutObjectCommand {
        id: key_id,
        label,
        domains,
        capabilities,
        algorithm: algorithm.into(),
        data,
    }))
}

/// Request parameters for `commands::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHMACKeyCommand(pub(crate) PutObjectCommand);

impl Command for PutHMACKeyCommand {
    type ResponseType = PutHMACKeyResponse;
}

/// Response from `commands::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct PutHMACKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutHMACKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutHMACKey;
}
