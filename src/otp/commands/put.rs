//! Put an existing OTP AEAD key into the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Otp_Aead_Key.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_otp_aead_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOtpAeadKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Serialized object
    pub data: Vec<u8>,
}

impl Command for PutOtpAeadKeyCommand {
    type ResponseType = PutOtpAeadKeyResponse;
}

/// Response from `command::put_otp_aead_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOtpAeadKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutOtpAeadKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutOtpAead;
}
