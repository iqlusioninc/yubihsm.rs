use crate::{
    algorithm,
    object::{self, SequenceId},
    Capability, Domain,
};
use serde::{Deserialize, Serialize};

/// Information about an object
///
/// This is a wrap-specific version of [`object::Info`]. It does not carry any
/// delegated_capabilities.
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
    pub algorithm: algorithm::Algorithm,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,

    /// How did this object originate? (generated, imported, etc)
    pub origin: object::Origin,

    /// Label of object
    pub label: object::Label,
}

impl From<object::Info> for Info {
    fn from(i: object::Info) -> Self {
        Self {
            capabilities: i.capabilities,
            object_id: i.object_id,
            length: i.length,
            domains: i.domains,
            object_type: i.object_type,
            algorithm: i.algorithm,
            sequence: i.sequence,
            origin: i.origin,
            label: i.label,
        }
    }
}

impl From<Info> for object::Info {
    fn from(i: Info) -> Self {
        Self {
            capabilities: i.capabilities,
            object_id: i.object_id,
            length: i.length,
            domains: i.domains,
            object_type: i.object_type,
            algorithm: i.algorithm,
            sequence: i.sequence,
            origin: i.origin,
            label: i.label,
            // This is a wrapped object, delegate capabilities applies to wrap keys themselves.
            // (and authentication keys).
            delegated_capabilities: Capability::empty(),
        }
    }
}
