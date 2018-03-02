//! Request data for `CommandType::ListObjects`

use responses::ListObjectsResponse;
use super::{Command, CommandType};
#[cfg(feature = "mockhsm")]
use super::{CommandMessage, Error};

/// Request data for `CommandType::ListObjects`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
#[derive(Debug)]
pub struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;
    type ResponseType = ListObjectsResponse;

    /// Serialize data
    // TODO: procedurally generate this
    fn into_vec(self) -> Vec<u8> {
        vec![]
    }

    /// Deserialize data
    #[cfg(feature = "mockhsm")]
    fn parse(command_msg: CommandMessage) -> Result<Self, Error> {
        if !command_msg.data.is_empty() {
            bail!("CommandType::ListObjects filters are not supported");
        }

        Ok(Self {})
    }
}
