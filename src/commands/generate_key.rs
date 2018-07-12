//! Generate keys within the `YubiHSM2`

use {Algorithm, Capability, Domain, ObjectId, ObjectLabel};

/// Parameters which are common to all key generation commands
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GenerateKeyParams {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domain in which the key will be accessible
    pub domains: Domain,

    /// Capability of the key
    pub capabilities: Capability,

    /// Key algorithm
    pub algorithm: Algorithm,
}
