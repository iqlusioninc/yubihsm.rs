//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use super::{Command, Response};
use {Adapter, Client, ClientError, CommandType, ObjectId, ObjectType, SequenceId};

/// List objects visible from the current session
pub fn list_objects<A: Adapter>(
    session: &mut Client<A>,
) -> Result<Vec<ListObjectsEntry>, ClientError> {
    // TODO: support for filtering objects
    session
        .send_command(ListObjectsCommand {})
        .map(|response| response.0)
}

/// Request parameters for `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Response from `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsResponse(pub(crate) Vec<ListObjectsEntry>);

impl Response for ListObjectsResponse {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;
}

/// Brief information about an object as included in `ListObjectsCommand`
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsEntry {
    /// Object identifier
    pub object_id: ObjectId,

    /// Object type
    pub object_type: ObjectType,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,
}
