//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use command::{Command, CommandCode};
use object::{ObjectId, ObjectType, SequenceId};
use response::Response;

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
    const COMMAND_CODE: CommandCode = CommandCode::ListObjects;
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
