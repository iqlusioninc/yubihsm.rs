//! Verify HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Verify_Hmac.html>

use super::hmac::HMACTag;
use super::{Command, Response};
use {CommandType, Connector, ObjectId, Session, SessionError};

/// Verify an HMAC tag of the given data with the given key ID
pub fn verify_hmac<C, D, T>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: D,
    tag: T,
) -> Result<(), SessionError>
where
    C: Connector,
    D: Into<Vec<u8>>,
    T: Into<HMACTag>,
{
    let result = session.send_encrypted_command(VerifyHMACCommand {
        key_id,
        tag: tag.into(),
        data: data.into(),
    })?;

    if result.0 == 1 {
        Ok(())
    } else {
        Err(command_err!(ResponseError, "HMAC verification failure"))
    }
}

/// Request parameters for `commands::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VerifyHMACCommand {
    /// ID of the key to verify the HMAC tag with
    pub key_id: ObjectId,

    /// HMAC tag to be verified
    pub tag: HMACTag,

    /// Data to be authenticated
    pub data: Vec<u8>,
}

impl Command for VerifyHMACCommand {
    type ResponseType = VerifyHMACResponse;
}

/// HMAC tags
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VerifyHMACResponse(pub(crate) u8);

impl Response for VerifyHMACResponse {
    const COMMAND_TYPE: CommandType = CommandType::VerifyHMAC;
}
