//! The `YubiHSM 2` doesnt' have a unified put object command, however all of the put object
//! commands share a common structure, i.e. `object::import::Params`

use crate::{object, Algorithm, Capability, Domain};
use serde::{Deserialize, Serialize};

/// Parameters used when importing objects into the HSM
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Params {
    /// ID of the object
    pub id: object::Id,

    /// Label for the object (40-bytes)
    pub label: object::Label,

    /// Domains in which the key will be accessible
    pub domains: Domain,

    /// Capabilities of the object
    pub capabilities: Capability,

    /// Object algorithm
    pub algorithm: Algorithm,
}

impl Params {
    /// Create minimal `import::Params` using the given `object::Id` and algorithm
    pub fn new(id: object::Id, algorithm: Algorithm) -> Self {
        Self {
            id,
            label: object::Label::default(),
            domains: Domain::empty(),
            capabilities: Capability::empty(),
            algorithm,
        }
    }
}
