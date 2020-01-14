//! Objects stored in the `MockHsm`

use super::{Object, Payload, WrappedObject, DEFAULT_AUTHENTICATION_KEY_LABEL};
use crate::{
    authentication::{self, DEFAULT_AUTHENTICATION_KEY_ID},
    mockhsm::{Error, ErrorKind},
    object::{Handle, Id, Info, Label, Origin, Type},
    serialization::{deserialize, serialize},
    wrap, Algorithm, Capability, Domain,
};
use anomaly::{fail, format_err};
use ring::aead::{self, AES_128_GCM, AES_256_GCM};
use std::collections::{btree_map::Iter as BTreeMapIter, BTreeMap};

/// Objects stored in the `MockHsm`
#[derive(Debug)]
pub(crate) struct Objects(BTreeMap<Handle, Object>);

impl Default for Objects {
    fn default() -> Self {
        let mut objects = BTreeMap::new();

        // Insert default authentication key
        let authentication_key_handle =
            Handle::new(DEFAULT_AUTHENTICATION_KEY_ID, Type::AuthenticationKey);

        let authentication_key_info = Info {
            object_id: DEFAULT_AUTHENTICATION_KEY_ID,
            object_type: Type::AuthenticationKey,
            algorithm: Algorithm::Authentication(authentication::Algorithm::YubicoAes),
            capabilities: Capability::all(),
            delegated_capabilities: Capability::all(),
            domains: Domain::all(),
            length: authentication::key::SIZE as u16,
            sequence: 1,
            origin: Origin::Imported,
            label: DEFAULT_AUTHENTICATION_KEY_LABEL.into(),
        };

        let authentication_key_payload = Payload::AuthenticationKey(authentication::Key::default());

        let _ = objects.insert(
            authentication_key_handle,
            Object {
                object_info: authentication_key_info,
                payload: authentication_key_payload,
            },
        );

        Objects(objects)
    }
}

impl Objects {
    /// Generate a new object in the MockHsm
    pub fn generate(
        &mut self,
        object_id: Id,
        object_type: Type,
        algorithm: Algorithm,
        label: Label,
        capabilities: Capability,
        delegated_capabilities: Capability,
        domains: Domain,
    ) {
        let payload = Payload::generate(algorithm);
        let length = payload.len();

        let object_info = Info {
            object_id,
            object_type,
            algorithm,
            capabilities,
            delegated_capabilities,
            domains,
            length,
            sequence: 1,
            origin: Origin::Generated,
            label,
        };

        let handle = Handle::new(object_id, object_type);

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(handle, object).is_none());
    }

    /// Get an object
    pub fn get(&self, object_id: Id, object_type: Type) -> Option<&Object> {
        self.0.get(&Handle::new(object_id, object_type))
    }

    /// Put a new object in the MockHsm
    pub fn put(
        &mut self,
        object_id: Id,
        object_type: Type,
        algorithm: Algorithm,
        label: Label,
        capabilities: Capability,
        delegated_capabilities: Capability,
        domains: Domain,
        data: &[u8],
    ) {
        let payload = Payload::new(algorithm, data);
        let length = payload.len();

        let object_info = Info {
            object_id,
            object_type,
            algorithm,
            capabilities,
            delegated_capabilities,
            domains,
            length,
            sequence: 1,
            origin: Origin::Imported,
            label,
        };

        let handle = Handle::new(object_id, object_type);

        let object = Object {
            object_info,
            payload,
        };

        assert!(self.0.insert(handle, object).is_none());
    }

    /// Remove an object
    pub fn remove(&mut self, object_id: Id, object_type: Type) -> Option<Object> {
        self.0.remove(&Handle::new(object_id, object_type))
    }

    /// Serialize an object as ciphertext
    pub fn wrap(
        &mut self,
        wrap_key_id: Id,
        object_id: Id,
        object_type: Type,
        wrap_nonce: &wrap::Nonce,
    ) -> Result<Vec<u8>, Error> {
        let wrap_key = match self.get(wrap_key_id, Type::WrapKey) {
            Some(k) => k,
            None => fail!(
                ErrorKind::ObjectNotFound,
                "no such wrap key: {:?}",
                wrap_key_id
            ),
        };

        let sealing_key = match wrap_key.algorithm().wrap().unwrap() {
            // TODO: actually use AES-CCM
            wrap::Algorithm::Aes128Ccm => {
                aead::UnboundKey::new(&AES_128_GCM, wrap_key.payload.as_ref())
            }
            wrap::Algorithm::Aes256Ccm => {
                aead::UnboundKey::new(&AES_256_GCM, wrap_key.payload.as_ref())
            }
            unsupported => fail!(
                ErrorKind::UnsupportedAlgorithm,
                "unsupported wrap key algorithm: {:?}",
                unsupported
            ),
        }
        .unwrap();

        let object_to_wrap = match self.get(object_id, object_type) {
            Some(o) => o,
            None => fail!(
                ErrorKind::ObjectNotFound,
                "no such {:?} object: {:?}",
                object_type,
                object_id
            ),
        };

        if !object_to_wrap
            .object_info
            .capabilities
            .contains(Capability::EXPORTABLE_UNDER_WRAP)
        {
            fail!(
                ErrorKind::AccessDenied,
                "object {:?} of type {:?} does not have EXPORT_UNDER_WRAP capability",
                object_id,
                object_type
            );
        }

        let mut object_info = object_to_wrap.object_info.clone();

        match object_info.origin {
            Origin::Generated => object_info.origin = Origin::WrappedGenerated,
            Origin::Imported => object_info.origin = Origin::WrappedImported,
            Origin::WrappedGenerated | Origin::WrappedImported => (),
        }

        let mut wrapped_object = serialize(&WrappedObject {
            object_info,
            data: object_to_wrap.payload.as_ref().into(),
        })
        .unwrap();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&wrap_nonce.as_ref()[..12]);

        aead::LessSafeKey::new(sealing_key)
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(b""),
                &mut wrapped_object,
            )
            .unwrap();

        Ok(wrapped_object)
    }

    /// Deserialize an encrypted object and insert it into the HSM
    pub fn unwrap<V: Into<Vec<u8>>>(
        &mut self,
        wrap_key_id: Id,
        wrap_nonce: &wrap::Nonce,
        ciphertext: V,
    ) -> Result<Handle, Error> {
        let opening_key = match self.get(wrap_key_id, Type::WrapKey) {
            Some(k) => match k.algorithm().wrap().unwrap() {
                wrap::Algorithm::Aes128Ccm => {
                    aead::UnboundKey::new(&AES_128_GCM, k.payload.as_ref())
                }
                wrap::Algorithm::Aes256Ccm => {
                    aead::UnboundKey::new(&AES_256_GCM, k.payload.as_ref())
                }
                unsupported => fail!(
                    ErrorKind::UnsupportedAlgorithm,
                    "unsupported wrap key algorithm: {:?}",
                    unsupported
                ),
            }
            .unwrap(),
            None => fail!(
                ErrorKind::ObjectNotFound,
                "no such wrap key: {:?}",
                wrap_key_id
            ),
        };

        let mut wrapped_data: Vec<u8> = ciphertext.into();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&wrap_nonce.as_ref()[..12]);

        let plaintext = aead::LessSafeKey::new(opening_key)
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(b""),
                &mut wrapped_data,
            )
            .map_err(|_| format_err!(ErrorKind::CryptoError, "error decrypting wrapped object!"))?;

        let unwrapped_object: WrappedObject = deserialize(plaintext).unwrap();

        let payload = Payload::new(
            unwrapped_object.object_info.algorithm,
            &unwrapped_object.data,
        );

        let object_key = Handle::new(
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
    pub fn iter(&self) -> Iter<'_> {
        self.0.iter()
    }
}

/// Iterator over objects
pub(crate) type Iter<'a> = BTreeMapIter<'a, Handle, Object>;
