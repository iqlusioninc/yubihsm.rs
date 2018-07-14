//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use super::{Command, Response};
use {CommandType, Connector, ObjectId, ObjectType, SequenceId, Session, SessionError};

/// List objects visible from the current session
pub fn list_objects<C: Connector>(
    session: &mut Session<C>,
) -> Result<Vec<ListObjectsEntry>, SessionError> {
    // TODO: support for filtering objects
    session
        .send_encrypted_command(ListObjectsCommand {})
        .map(|response| response.0)
}

/// Request parameters for `commands::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Response from `commands::list_objects`
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
