use {Algorithm, Capability, Domain, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};

/// Information about an object
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Info {
    /// Capabilities (bitfield)
    pub capabilities: Capability,

    /// Object identifier
    pub object_id: ObjectId,

    /// Length of object in bytes
    pub length: u16,

    /// Domains from which object is accessible
    pub domains: Domain,

    /// Object type
    pub object_type: ObjectType,

    /// Algorithm this object is intended to be used with
    pub algorithm: Algorithm,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,

    /// How did this object originate? (generated, imported, etc)
    pub origin: ObjectOrigin,

    /// Label of object
    pub label: ObjectLabel,

    /// Delegated Capabilities (bitfield)
    pub delegated_capabilities: Capability,
}
