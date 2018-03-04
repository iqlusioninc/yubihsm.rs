//! Request data for `CommandType::ListObjects`

use responses::ListObjectsResponse;
use super::{Command, CommandType};

/// Request data for `CommandType::ListObjects`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;
    type ResponseType = ListObjectsResponse;
}
