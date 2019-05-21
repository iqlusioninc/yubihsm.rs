//! Object handles

use crate::object;
use serde::{Deserialize, Serialize};

/// Objects in the HSM are keyed by a tuple of their type an object::Id
/// (i.e. multiple objects of different types can have the same object::Id)
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
pub struct Handle {
    /// ID of the object
    pub object_id: object::Id,

    /// Type of object
    pub object_type: object::Type,
}

impl Handle {
    /// Create a new object handle
    pub fn new(object_id: object::Id, object_type: object::Type) -> Self {
        Self {
            object_id,
            object_type,
        }
    }
}
