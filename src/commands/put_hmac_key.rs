//! Put an existing HMAC key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
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
) -> Result<ObjectId, SessionError> {
    let hmac_key = key_bytes.into();

    if hmac_key.len() < HMAC_MIN_KEY_SIZE || hmac_key.len() > algorithm.max_key_len() {
        command_fail!(
            ProtocolError,
            "invalid key length for {:?}: {} (min {}, max {})",
            algorithm,
            hmac_key.len(),
            HMAC_MIN_KEY_SIZE,
            algorithm.max_key_len()
        );
    }

    session
        .send_encrypted_command(PutHMACKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            hmac_key,
        })
        .map(|response| response.key_id)
}

/// Request parameters for `commands::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHMACKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub hmac_key: Vec<u8>,
}

impl Command for PutHMACKeyCommand {
    type ResponseType = PutHMACKeyResponse;
}

/// Response from `commands::put_hmac_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutHMACKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutHMACKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutHMACKey;
}
