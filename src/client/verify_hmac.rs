//! Verify HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Verify_Hmac.html>

use super::sign_hmac::HmacTag;
use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Request parameters for `command::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VerifyHMACCommand {
    /// ID of the key to verify the HMAC tag with
    pub key_id: object::Id,

    /// HMAC tag to be verified
    pub tag: HmacTag,

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
    const COMMAND_CODE: command::Code = command::Code::VerifyHmac;
}
