//! Put an existing OTP AEAD key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>

use super::put_object::PutObjectParams;
use super::{Command, Response};
use session::SessionErrorKind::ProtocolError;
use {
    Adapter, Capability, CommandType, Domain, ObjectId, ObjectLabel, OtpAlg, Session, SessionError,
};

/// Put an existing OTP AEAD key into the `YubiHSM2`
///
/// Valid algorithms
pub fn put_otp_aead_key<A: Adapter, T: Into<Vec<u8>>>(
    session: &mut Session<A>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: OtpAlg,
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
        .send_command(PutOTPAEADKeyCommand {
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
