//! Generate keys within the `YubiHSM 2`

use crate::{object, Algorithm, Capability, Domain};
use serde::{Deserialize, Serialize};

/// Parameters which are common to all key generation commands
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Params {
    /// ID of the key
    pub key_id: object::Id,

    /// Label for the key (40-bytes)
    pub label: object::Label,

    /// Domain in which the key will be accessible
    pub domains: Domain,

    /// Capability of the key
    pub capabilities: Capability,

    /// Key algorithm
    pub algorithm: Algorithm,
}
