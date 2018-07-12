use super::{ObjectId, ObjectType};

/// Objects in the HSM are keyed by a tuple of their type an ObjectId
/// (i.e. multiple objects of different types can have the same ObjectId)
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub(crate) struct Handle {
    /// ID of the object
    pub object_id: ObjectId,

    /// Type of object
    pub object_type: ObjectType,
}

impl Handle {
    /// Create a new object handle
    pub fn new(object_id: ObjectId, object_type: ObjectType) -> Self {
        Self {
            object_id,
            object_type,
        }
    }
}
