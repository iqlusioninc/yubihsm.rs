//! Objects stored inside of the `MockHSM`

use rand::{OsRng, Rng};
use ring::signature::Ed25519KeyPair;
use std::collections::HashMap;
use untrusted;

use {
    Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId,
};

/// Objects stored in the `MockHSM`
#[derive(Default)]
pub struct Objects {
    // TODO: other object types besides Ed25519 keys
    pub ed25519_keys: HashMap<ObjectId, Object<Ed25519KeyPair>>,
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

impl Object<Ed25519KeyPair> {
    pub fn new(label: ObjectLabel, capabilities: Capabilities, domains: Domains) -> Self {
        let mut csprng = OsRng::new().unwrap();

        let mut seed_bytes = [0u8; 32];
        csprng.fill_bytes(&mut seed_bytes);

        let seed = untrusted::Input::from(&seed_bytes);

        Self {
            value: Ed25519KeyPair::from_seed_unchecked(seed).unwrap(),
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
