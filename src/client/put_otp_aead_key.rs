//! Put an existing OTP AEAD key into the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Otp_Aead_Key.html>

use super::put_object::PutObjectParams;
use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::put_otp_aead_key`
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

/// Response from `command::put_otp_aead_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOTPAEADKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for PutOTPAEADKeyResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutOTPAEAD;
}
