//! Information about objects

use super::SequenceId;
use crate::{object, Algorithm, Capability, Domain};
use serde::{Deserialize, Serialize};

/// Information about an object
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Info {
    /// Capabilities (bitfield)
    pub capabilities: Capability,

    /// Object identifier
    pub object_id: object::Id,

    /// Length of object in bytes
    pub length: u16,

    /// Domains from which object is accessible
    pub domains: Domain,

    /// Object type
    pub object_type: object::Type,

    /// Algorithm this object is intended to be used with
    pub algorithm: Algorithm,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,

    /// How did this object originate? (generated, imported, etc)
    pub origin: object::Origin,

    /// Label of object
    pub label: object::Label,

    /// Delegated Capabilities (bitfield)
    pub delegated_capabilities: Capability,
}
