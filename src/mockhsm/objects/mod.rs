//! Objects stored inside of the `MockHSM`

#![allow(unknown_lints, too_many_arguments)]

mod ecdsa;
mod payload;

use failure::Error;
use ring::aead::{self, AES_128_GCM, AES_256_GCM, OpeningKey, SealingKey};
use std::collections::hash_map::Iter as HashMapIter;
use std::collections::HashMap;

pub(crate) use self::payload::Payload;
use serializers::{deserialize, serialize};
use {
    Algorithm, Capability, Domain, ObjectId, ObjectInfo, ObjectLabel, ObjectOrigin, ObjectType,
    WrapNonce, WrappedData,
};

/// Size of the wrap algorithm's MAC tag. The MockHSM uses AES-GCM instead of
/// AES-CCM as there isn't a readily available Rust implementation
const WRAPPED_DATA_MAC_SIZE: usize = 16;

/// Objects in the HSM are keyed by a tuple of their type an ObjectId
/// (i.e. multiple objects of different types can have the same ObjectId)
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) struct ObjectKey {
    /// Type of object
    pub object_type: ObjectType,

    /// ID of the object
    pub object_id: ObjectId,
}

/// Iterator over objects
pub(crate) type Iter<'a> = HashMapIter<'a, ObjectKey, Object>;

/// Objects stored in the `MockHSM`
pub(crate) struct Objects(HashMap<ObjectKey, Object>);

impl Default for Objects {
    fn default() -> Self {
        Objects(HashMap::new())
    }
}

impl Objects {
    /// Generate a new object in the MockHSM
    pub fn generate(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
        algorithm: Algorithm,
        label: ObjectLabel,
        capabilities: Capability,
        delegated_capabilities: Capability,
        domains: Domain,
    ) {
        let payload = Payload::generate(algorithm);
        let length = payload.len();

        let object_info = ObjectInfo {
            object_id,
            object_type,
            algorithm,
            capabilities,
            delegated_capabilities,
            domains,
            length,
            sequence: 1,
            origin: ObjectOrigin::Generated,
            label,
        };

        let key = ObjectKey {
            object_type,
            object_id,
        };

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(key, object).is_none());
    }

    /// Get an object
    pub fn get(&self, object_type: ObjectType, object_id: ObjectId) -> Option<&Object> {
        self.0.get(&ObjectKey {
            object_type,
            object_id,
        })
    }

    /// Put a new object in the MockHSM
    pub fn put(
        &mut self,
        object_type: ObjectType,
        object_id: ObjectId,
        algorithm: Algorithm,
        label: ObjectLabel,
        capabilities: Capability,
        delegated_capabilities: Capability,
        domains: Domain,
        data: &[u8],
    ) {
        let payload = Payload::new(algorithm, data);
        let length = payload.len();

        let object_info = ObjectInfo {
            object_id,
            object_type,
            algorithm,
            capabilities,
            delegated_capabilities,
            domains,
            length,
            sequence: 1,
            origin: ObjectOrigin::Imported,
            label,
        };

        let key = ObjectKey {
            object_id,
            object_type,
        };

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(key, object).is_none());
    }

    /// Remove an object
    pub fn remove(&mut self, object_id: ObjectId, object_type: ObjectType) -> Option<Object> {
        self.0.remove(&ObjectKey {
            object_type,
            object_id,
        })
    }

    /// Serialize an object as ciphertext
    pub fn wrap(
        &mut self,
        wrap_key_id: ObjectId,
        object_type: ObjectType,
        object_id: ObjectId,
        nonce: &WrapNonce,
    ) -> Result<WrappedData, Error> {
        let wrap_key = match self.get(ObjectType::WrapKey, wrap_key_id) {
            Some(k) => k,
            None => bail!("no such wrap key: {:?}", wrap_key_id),
        };

        let sealing_key = match wrap_key.algorithm() {
            // TODO: actually use AES-CCM
            Algorithm::AES128_CCM_WRAP => {
                SealingKey::new(&AES_128_GCM, &wrap_key.payload.private_key_bytes())
            }
            Algorithm::AES256_CCM_WRAP => {
                SealingKey::new(&AES_256_GCM, &wrap_key.payload.private_key_bytes())
            }
            unsupported => bail!("unsupported wrap key algorithm: {:?}", unsupported),
        }.unwrap();

        let object_to_wrap = match self.get(object_type, object_id) {
            Some(o) => o,
            None => bail!("no such {:?} object: {:?}", object_type, object_id),
        };

        if !object_to_wrap
            .object_info
            .capabilities
            .contains(Capability::EXPORT_UNDER_WRAP)
        {
            bail!(
                "object {:?} of type {:?} does not have EXPORT_UNDER_WRAP capability",
                object_id,
                object_type
            );
        }

        let mut object_info = object_to_wrap.object_info.clone();

        match object_info.origin {
            ObjectOrigin::Generated => object_info.origin = ObjectOrigin::WrappedGenerated,
            ObjectOrigin::Imported => object_info.origin = ObjectOrigin::WrappedImported,
            ObjectOrigin::WrappedGenerated | ObjectOrigin::WrappedImported => (),
        }

        let mut wrapped_object = serialize(&WrappedObject {
            object_info,
            data: object_to_wrap.payload.private_key_bytes(),
        }).unwrap();

        // Make room for the MAC
        wrapped_object.extend_from_slice(&[0u8; WRAPPED_DATA_MAC_SIZE]);

        aead::seal_in_place(
            &sealing_key,
            &nonce.as_ref()[..12],
            b"",
            &mut wrapped_object,
            WRAPPED_DATA_MAC_SIZE,
        ).unwrap();

        Ok(WrappedData(wrapped_object))
    }

    /// Deserialize an encrypted object and insert it into the HSM
    pub fn unwrap(
        &mut self,
        wrap_key_id: ObjectId,
        nonce: &WrapNonce,
        ciphertext: &WrappedData,
    ) -> Result<ObjectKey, Error> {
        let opening_key = match self.get(ObjectType::WrapKey, wrap_key_id) {
            Some(k) => match k.algorithm() {
                Algorithm::AES128_CCM_WRAP => {
                    OpeningKey::new(&AES_128_GCM, &k.payload.private_key_bytes())
                }
                Algorithm::AES256_CCM_WRAP => {
                    OpeningKey::new(&AES_256_GCM, &k.payload.private_key_bytes())
                }
                unsupported => bail!("unsupported wrap key algorithm: {:?}", unsupported),
            }.unwrap(),
            None => bail!("no such wrap key: {:?}", wrap_key_id),
        };

        let mut wrapped_data = Vec::from(ciphertext.as_ref());

        if aead::open_in_place(
            &opening_key,
            &nonce.as_ref()[..12],
            b"",
            0,
            &mut wrapped_data,
        ).is_err()
        {
            bail!("error decrypting wrapped object!");
        }

        let plaintext_len: usize = wrapped_data
            .len()
            .checked_sub(WRAPPED_DATA_MAC_SIZE)
            .unwrap();

        let unwrapped_object: WrappedObject = deserialize(&wrapped_data[..plaintext_len]).unwrap();

        let payload = Payload::new(
            unwrapped_object.object_info.algorithm,
            &unwrapped_object.data,
        );

        let object_key = ObjectKey {
            object_type: unwrapped_object.object_info.object_type,
            object_id: unwrapped_object.object_info.object_id,
        };

        let object = Object {
            object_info: unwrapped_object.object_info,
            payload,
        };

        assert!(self.0.insert(object_key.clone(), object).is_none());

        Ok(object_key)
    }

    /// Iterate over the objects
    pub fn iter(&self) -> Iter {
        self.0.iter()
    }
}

/// An individual object in the `MockHSM`, specialized for a given object type
pub(crate) struct Object {
    pub object_info: ObjectInfo,
    pub payload: Payload,
}

impl Object {
    /// Get the algorithm of the payload
    pub fn algorithm(&self) -> Algorithm {
        self.payload.algorithm()
    }
}

/// A serialized object which can be exported/imported
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrappedObject {
    pub object_info: ObjectInfo,
    pub data: Vec<u8>,
}

impl<'a> From<&'a Object> for WrappedObject {
    fn from(obj: &'a Object) -> Self {
        Self {
            object_info: obj.object_info.clone(),
            data: obj.payload.private_key_bytes(),
        }
    }
}
