//! Objects stored inside of the `MockHSM`

use std::collections::HashMap;
use rand::OsRng;
use sha2::Sha512;

use ed25519_dalek::Keypair as Ed25519Keypair;

use {Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};

/// Objects stored in the `MockHSM`
#[derive(Default)]
pub struct Objects {
    // TODO: other object types besides Ed25519 keys
    pub ed25519_keys: HashMap<ObjectId, Object<Ed25519Keypair>>,
}

impl Objects {
    /// Create a new MockHSM object store
    pub fn new() -> Self {
        Objects {
            ed25519_keys: HashMap::new(),
        }
    }
}

/// An individual object in the `MockHSM`, specialized for a given object type
pub struct Object<T> {
    pub value: T,
    pub object_type: ObjectType,
    pub algorithm: Algorithm,
    pub capabilities: Capabilities,
    pub delegated_capabilities: Capabilities,
    pub domains: Domains,
    pub length: u16,
    pub sequence: SequenceId,
    pub origin: ObjectOrigin,
    pub label: ObjectLabel,
}

impl Object<Ed25519Keypair> {
    pub fn new(label: ObjectLabel, capabilities: Capabilities, domains: Domains) -> Self {
        let mut cspring = OsRng::new().unwrap();

        Self {
            value: Ed25519Keypair::generate::<Sha512>(&mut cspring),
            object_type: ObjectType::Asymmetric,
            algorithm: Algorithm::EC_ED25519,
            capabilities,
            delegated_capabilities: Capabilities::default(),
            domains,
            length: 24,
            sequence: 1,
            origin: ObjectOrigin::Generated,
            label,
        }
    }
}
