//! Compute HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Hmac.html>

use crate::{
    command::{self, Command},
    hmac, object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignHmacCommand {
    /// ID of the HMAC key
    pub key_id: object::Id,

    /// Data to be authenticated
    pub data: Vec<u8>,
}

impl Command for SignHmacCommand {
    type ResponseType = SignHmacResponse;
}

/// Sign HMAC response
#[derive(Serialize, Deserialize, Debug)]
pub struct SignHmacResponse(pub(crate) hmac::Tag);

impl Response for SignHmacResponse {
    const COMMAND_CODE: command::Code = command::Code::SignHmac;
}

impl From<SignHmacResponse> for hmac::Tag {
    fn from(response: SignHmacResponse) -> hmac::Tag {
        response.0
    }
}
