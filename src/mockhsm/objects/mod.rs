//! Objects stored inside of the `MockHSM`

#![allow(unknown_lints, too_many_arguments)]

mod ecdsa;
mod payload;

use failure::Error;
use ring::aead::{self, AES_128_GCM, AES_256_GCM, OpeningKey, SealingKey};
use std::collections::hash_map::Iter as HashMapIter;
use std::collections::HashMap;

pub(crate) use self::payload::Payload;
use auth_key::{AuthKey, AUTH_KEY_DEFAULT_ID, AUTH_KEY_SIZE};
use serializers::{deserialize, serialize};
use {
    Algorithm, Capability, Domain, ObjectHandle, ObjectId, ObjectInfo, ObjectLabel, ObjectOrigin,
    ObjectType, WrapNonce,
};

/// Size of the wrap algorithm's MAC tag. The MockHSM uses AES-GCM instead of
/// AES-CCM as there isn't a readily available Rust implementation
const WRAPPED_DATA_MAC_SIZE: usize = 16;

/// Label for the default auth key
const DEFAULT_AUTH_KEY_LABEL: &str = "DEFAULT AUTHKEY CHANGE THIS ASAP";

/// Iterator over objects
pub(crate) type Iter<'a> = HashMapIter<'a, ObjectHandle, Object>;

/// Objects stored in the `MockHSM`
pub(crate) struct Objects(HashMap<ObjectHandle, Object>);

impl Default for Objects {
    fn default() -> Self {
        let mut objects = HashMap::new();

        // Insert default authentication key
        let auth_key_handle = ObjectHandle::new(AUTH_KEY_DEFAULT_ID, ObjectType::AuthKey);

        let auth_key_info = ObjectInfo {
            object_id: AUTH_KEY_DEFAULT_ID,
            object_type: ObjectType::AuthKey,
            algorithm: Algorithm::YUBICO_AES_AUTH,
            capabilities: Capability::all(),
            delegated_capabilities: Capability::all(),
            domains: Domain::all(),
            length: AUTH_KEY_SIZE as u16,
            sequence: 1,
            origin: ObjectOrigin::Imported,
            label: DEFAULT_AUTH_KEY_LABEL.into(),
        };

        let auth_key_payload = Payload::AuthKey(AuthKey::default());

        let _ = objects.insert(
            auth_key_handle,
            Object {
                object_info: auth_key_info,
                payload: auth_key_payload,
            },
        );

        Objects(objects)
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

        let handle = ObjectHandle::new(object_id, object_type);

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(handle, object).is_none());
    }

    /// Get an object
    pub fn get(&self, object_id: ObjectId, object_type: ObjectType) -> Option<&Object> {
        self.0.get(&ObjectHandle::new(object_id, object_type))
    }

    /// Put a new object in the MockHSM
    pub fn put(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
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

        let handle = ObjectHandle::new(object_id, object_type);

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(handle, object).is_none());
    }

    /// Remove an object
    pub fn remove(&mut self, object_id: ObjectId, object_type: ObjectType) -> Option<Object> {
        self.0.remove(&ObjectHandle::new(object_id, object_type))
    }

    /// Serialize an object as ciphertext
    pub fn wrap(
        &mut self,
        wrap_key_id: ObjectId,
        object_id: ObjectId,
        object_type: ObjectType,
        nonce: &WrapNonce,
    ) -> Result<Vec<u8>, Error> {
        let wrap_key = match self.get(wrap_key_id, ObjectType::WrapKey) {
            Some(k) => k,
            None => bail!("no such wrap key: {:?}", wrap_key_id),
        };

        let sealing_key = match wrap_key.algorithm() {
            // TODO: actually use AES-CCM
            Algorithm::AES128_CCM_WRAP => SealingKey::new(&AES_128_GCM, wrap_key.payload.as_ref()),
            Algorithm::AES256_CCM_WRAP => SealingKey::new(&AES_256_GCM, wrap_key.payload.as_ref()),
            unsupported => bail!("unsupported wrap key algorithm: {:?}", unsupported),
        }.unwrap();

        let object_to_wrap = match self.get(object_id, object_type) {
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
            data: object_to_wrap.payload.as_ref().into(),
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

        Ok(wrapped_object)
    }

    /// Deserialize an encrypted object and insert it into the HSM
    pub fn unwrap<V: Into<Vec<u8>>>(
        &mut self,
        wrap_key_id: ObjectId,
        nonce: &WrapNonce,
        ciphertext: V,
    ) -> Result<ObjectHandle, Error> {
        let opening_key = match self.get(wrap_key_id, ObjectType::WrapKey) {
            Some(k) => match k.algorithm() {
                Algorithm::AES128_CCM_WRAP => OpeningKey::new(&AES_128_GCM, k.payload.as_ref()),
                Algorithm::AES256_CCM_WRAP => OpeningKey::new(&AES_256_GCM, k.payload.as_ref()),
                unsupported => bail!("unsupported wrap key algorithm: {:?}", unsupported),
            }.unwrap(),
            None => bail!("no such wrap key: {:?}", wrap_key_id),
        };

        let mut wrapped_data: Vec<u8> = ciphertext.into();

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

        let object_key = ObjectHandle::new(
            unwrapped_object.object_info.object_id,
            unwrapped_object.object_info.object_type,
        );

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
            data: obj.payload.as_ref().into(),
        }
    }
}
