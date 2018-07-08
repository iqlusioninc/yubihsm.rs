//! Objects stored inside of the `MockHSM`

mod ecdsa;
mod payload;

use std::collections::hash_map::Iter as HashMapIter;
use std::collections::HashMap;

pub(crate) use self::payload::Payload;
use {Algorithm, Capability, Domain, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};

/// Iterator over objects
pub(crate) type Iter<'a> = HashMapIter<'a, ObjectId, Object>;

/// Objects stored in the `MockHSM`
pub(crate) struct Objects(HashMap<ObjectId, Object>);

impl Default for Objects {
    fn default() -> Self {
        Objects(HashMap::new())
    }
}

impl Objects {
    /// Generate a new object in the MockHSM
    pub fn generate(
        &mut self,
        id: ObjectId,
        algorithm: Algorithm,
        label: ObjectLabel,
        capabilities: Capability,
        domains: Domain,
    ) {
        let payload = Payload::generate(algorithm);
        let length = payload.len();

        let object = Object {
            payload,
            object_type: ObjectType::Asymmetric, // TODO: other object types
            capabilities,
            delegated_capabilities: Capability::default(),
            domains,
            length,
            sequence: 1,
            origin: ObjectOrigin::Generated,
            label,
        };

        assert!(self.0.insert(id, object).is_none());
    }

    /// Get an object
    pub fn get(&self, id: ObjectId) -> Option<&Object> {
        self.0.get(&id)
    }

    /// Put a new object in the MockHSM
    pub fn put(
        &mut self,
        id: ObjectId,
        algorithm: Algorithm,
        label: ObjectLabel,
        capabilities: Capability,
        domains: Domain,
        data: &[u8],
    ) {
        let payload = Payload::new(algorithm, data);
        let length = payload.len();

        let object = Object {
            payload,
            object_type: ObjectType::Asymmetric, // TODO: other object types
            capabilities,
            delegated_capabilities: Capability::default(),
            domains,
            length,
            sequence: 1,
            origin: ObjectOrigin::Imported,
            label,
        };

        assert!(self.0.insert(id, object).is_none());
    }

    /// Remove an object
    pub fn remove(&mut self, id: ObjectId) -> Option<Object> {
        self.0.remove(&id)
    }

    /// Iterate over the objects
    pub fn iter(&self) -> Iter {
        self.0.iter()
    }
}

/// An individual object in the `MockHSM`, specialized for a given object type
pub(crate) struct Object {
    pub payload: Payload,
    pub object_type: ObjectType,
    pub capabilities: Capability,
    pub delegated_capabilities: Capability,
    pub domains: Domain,
    pub length: u16,
    pub sequence: SequenceId,
    pub origin: ObjectOrigin,
    pub label: ObjectLabel,
}

impl Object {
    /// Get the algorithm of the payload
    pub fn algorithm(&self) -> Algorithm {
        self.payload.algorithm()
    }
}
