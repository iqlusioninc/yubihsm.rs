//! The `YubiHSM2` doesnt' have a unified put object command, however all of the put object
//! commands share a common structure, i.e. `object::ImportParams`

use crate::{Algorithm, Capability, Domain};

/// Parameters used when importing objects into the HSM
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportParams {
    /// ID of the object
    pub id: super::Id,

    /// Label for the object (40-bytes)
    pub label: super::Label,

    /// Domains in which the key will be accessible
    pub domains: Domain,

    /// Capabilities of the object
    pub capabilities: Capability,

    /// Object algorithm
    pub algorithm: Algorithm,
}
