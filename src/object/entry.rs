//! Object entries in list objects output

use crate::object;
use serde::{Deserialize, Serialize};

/// Brief information about an object as included in `ListObjectsCommand`
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Entry {
    /// Object identifier
    pub object_id: object::Id,

    /// Object type
    pub object_type: object::Type,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: object::SequenceId,
}
