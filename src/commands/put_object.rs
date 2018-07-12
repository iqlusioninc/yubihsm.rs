//! The `YubiHSM2` doesnt' have a unified put object command, however all of the put object
//! commands share a common structure, which is what is below.

use {Algorithm, Capability, Domain, ObjectId, ObjectLabel};

/// Common parameters to all put object commands
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutObjectParams {
    /// ID of the object
    pub id: ObjectId,

    /// Label for the object (40-bytes)
    pub label: ObjectLabel,

    /// Domains in which the key will be accessible
    pub domains: Domain,

    /// Capabilities of the object
    pub capabilities: Capability,

    /// Object algorithm
    pub algorithm: Algorithm,
}
