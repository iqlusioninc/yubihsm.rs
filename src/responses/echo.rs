//! Response from `CommandType::Echo`

use super::{CommandType, Response};

/// Response from `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct EchoResponse {
    /// Echo response
    pub message: Vec<u8>,
}

impl Response for EchoResponse {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
}
