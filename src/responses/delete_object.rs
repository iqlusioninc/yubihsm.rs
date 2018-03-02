//! Response from `CommandType::DeleteObject`

use failure::Error;
use super::{CommandType, Response};

/// Response from `CommandType::DeleteObject`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Debug)]
pub struct DeleteObjectResponse {}

impl Response for DeleteObjectResponse {
    const COMMAND_TYPE: CommandType = CommandType::DeleteObject;

    /// Parse response from HSM
    // TODO: procedurally generate this
    fn parse(_bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(Self {})
    }

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8> {
        vec![]
    }
}
