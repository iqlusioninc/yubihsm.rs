//! Put an existing OTP AEAD key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use {
    Capability, CommandType, Connector, Domain, OTPAlgorithm, ObjectId, ObjectLabel, Session,
    SessionError,
};

/// Put an existing OTP AEAD key into the `YubiHSM2`
///
/// Valid algorithms
pub fn put_otp_aead_key<C: Connector, T: Into<Vec<u8>>>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: OTPAlgorithm,
    key_bytes: T,
) -> Result<ObjectId, SessionError> {
    let data = key_bytes.into();

    if data.len() != algorithm.key_len() {
        command_fail!(
            ProtocolError,
            "invalid key length for {:?}: {} (expected {})",
            algorithm,
            data.len(),
            algorithm.key_len()
        );
    }

    session
        .send_encrypted_command(PutOTPAEADKeyCommand {
            params: PutObjectParams {
                id: key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            },
            data,
        })
        .map(|response| response.key_id)
}

/// Request parameters for `commands::put_otp_aead_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOTPAEADKeyCommand {
    /// Common parameters to all put object commands
    pub params: PutObjectParams,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutOTPAEADKeyCommand {
    type ResponseType = PutOTPAEADKeyResponse;
}

/// Response from `commands::put_otp_aead_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOTPAEADKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutOTPAEADKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutOTPAEAD;
}
