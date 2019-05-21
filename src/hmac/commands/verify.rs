//! Verify HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Verify_Hmac.html>

use crate::{
    command::{self, Command},
    hmac, object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VerifyHmacCommand {
    /// ID of the key to verify the HMAC tag with
    pub key_id: object::Id,

    /// HMAC tag to be verified
    pub tag: hmac::Tag,

    /// Data to be authenticated
    pub data: Vec<u8>,
}

impl Command for VerifyHmacCommand {
    type ResponseType = VerifyHmacResponse;
}

/// HMAC tags
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct VerifyHmacResponse(pub(crate) u8);

impl Response for VerifyHmacResponse {
    const COMMAND_CODE: command::Code = command::Code::VerifyHmac;
}
