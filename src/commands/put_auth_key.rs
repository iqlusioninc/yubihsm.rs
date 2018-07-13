//! Put an existing auth key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authkey.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use {
    AuthAlgorithm, AuthKey, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel,
    Session, SessionError,
};

/// Put an existing auth key into the `YubiHSM2`
#[allow(unknown_lints, too_many_arguments)]
pub fn put_auth_key<C: Connector, K: Into<AuthKey>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    delegated_capabilities: Capability,
    algorithm: AuthAlgorithm,
    auth_key: K,
) -> Result<ObjectId, SessionError> {
    session
        .send_encrypted_command(PutAuthKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            delegated_capabilities,
            auth_key: auth_key.into(),
        })
        .map(|response| response.key_id)
}

/// Request parameters for `commands::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Authentication key
    pub auth_key: AuthKey,
}

impl Command for PutAuthKeyCommand {
    type ResponseType = PutAuthKeyResponse;
}

/// Response from `commands::put_auth_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutAuthKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutAuthKey;
}
