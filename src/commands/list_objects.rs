//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use std::ops::Index;
use std::slice::Iter;

use super::{Command, Response};
use {CommandType, Connector, ObjectId, ObjectType, SequenceId, Session, SessionError};

/// List objects visible from the current session
pub fn list_objects<C: Connector>(
    session: &mut Session<C>,
) -> Result<ListObjectsResponse, SessionError> {
    // TODO: support for filtering objects
    session.send_encrypted_command(ListObjectsCommand {})
}

/// Request parameters for `commands::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Response from `commands::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsResponse(pub Vec<ListObjectsEntry>);

impl Response for ListObjectsResponse {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;
}

impl ListObjectsResponse {
    /// Number of entries in the response
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Are there no objects in the response?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the objects in the response
    #[inline]
    pub fn iter(&self) -> Iter<ListObjectsEntry> {
        self.0.iter()
    }
}

impl Index<usize> for ListObjectsResponse {
    type Output = ListObjectsEntry;

    fn index(&self, i: usize) -> &ListObjectsEntry {
        &self.0[i]
    }
}

/// Brief information about an object as included in `ListObjectsCommand`
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsEntry {
    /// Object identifier
    pub id: ObjectId,

    /// Object type
    pub object_type: ObjectType,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,
}
