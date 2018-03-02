//! Response from `CommandType::Echo`

use failure::Error;
use super::{CommandType, Response};

/// Response from `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Debug)]
pub struct EchoResponse {
    /// Echo response
    pub message: Vec<u8>,
}

impl Response for EchoResponse {
    const COMMAND_TYPE: CommandType = CommandType::Echo;

    /// Parse response from HSM
    // TODO: procedurally generate this
    fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(Self { message: bytes })
    }

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8> {
        self.message
    }
}
