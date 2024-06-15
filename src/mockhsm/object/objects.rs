//! Objects stored in the `MockHsm`

use super::{Object, Payload, WrappedObject, DEFAULT_AUTHENTICATION_KEY_LABEL};
use crate::{
    asymmetric,
    attestation::DEFAULT_ATTESTATION_KEY_ID,
    authentication::{self, DEFAULT_AUTHENTICATION_KEY_ID},
    mockhsm::{Error, ErrorKind},
    object::{Handle, Id, Info, Label, Origin, Type},
    opaque,
    serialization::{deserialize, serialize},
    wrap, Algorithm, Capability, Domain,
};
use aes::cipher::consts::{U13, U16};
use ccm::aead::{AeadInPlace, KeyInit};
use der::{
    asn1::{GeneralizedTime, UtcTime},
    DateTime, Encode,
};
use rand_core::OsRng;
use spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use std::{
    collections::{btree_map::Iter as MapIter, BTreeMap as Map},
    str::FromStr,
};
use x509_cert::{
    builder::{self, profile::BuilderProfile, Builder, CertificateBuilder},
    ext::Extension,
    name::Name,
    serial_number,
    time::{Time, Validity},
    Certificate, TbsCertificate,
};

/// AES-CCM with a 128-bit key
pub(crate) type Aes128Ccm = ccm::Ccm<aes::Aes128, U16, U13>;

/// AES-CCM with a 192-bit key
pub(crate) type Aes192Ccm = ccm::Ccm<aes::Aes192, U16, U13>;

/// AES-CCM with a 256-bit key
pub(crate) type Aes256Ccm = ccm::Ccm<aes::Aes256, U16, U13>;

/// AES-CCM key
#[allow(clippy::large_enum_variant)]
pub(crate) enum AesCcmKey {
    /// AES-CCM with a 128-bit key
    Aes128(Aes128Ccm),

    /// AES-CCM with a 192-bit key
    Aes192(Aes192Ccm),

    /// AES-CCM with a 256-bit key
    Aes256(Aes256Ccm),
}

impl AesCcmKey {
    /// Encrypt data in-place.
    #[allow(clippy::ptr_arg)]
    pub fn encrypt_in_place(
        &self,
        nonce: &wrap::Nonce,
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match self {
            AesCcmKey::Aes128(ccm) => {
                ccm.encrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
            AesCcmKey::Aes192(ccm) => {
                ccm.encrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
            AesCcmKey::Aes256(ccm) => {
                ccm.encrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
        }
        .map_err(|_| format_err!(ErrorKind::CryptoError, "error encrypting wrapped object!").into())
    }

    /// Decrypt data in-place.
    #[allow(clippy::ptr_arg)]
    pub fn decrypt_in_place(
        &self,
        nonce: &wrap::Nonce,
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), Error> {
        match self {
            AesCcmKey::Aes128(ccm) => {
                ccm.decrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
            AesCcmKey::Aes192(ccm) => {
                ccm.decrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
            AesCcmKey::Aes256(ccm) => {
                ccm.decrypt_in_place(&nonce.0.into(), associated_data, buffer)
            }
        }
        .map_err(|_| format_err!(ErrorKind::CryptoError, "error decrypting wrapped object!").into())
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            AesCcmKey::Aes128(_) => Algorithm::Wrap(wrap::Algorithm::Aes128Ccm),
            AesCcmKey::Aes192(_) => Algorithm::Wrap(wrap::Algorithm::Aes192Ccm),
            AesCcmKey::Aes256(_) => Algorithm::Wrap(wrap::Algorithm::Aes256Ccm),
        }
    }
}

/// Objects stored in the `MockHsm`
#[derive(Debug)]
pub(crate) struct Objects(Map<Handle, Object>);

impl Default for Objects {
    fn default() -> Self {
        let mut objects = Map::new();

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

        // Key used for attestation by default
        let attestation_key = p256::SecretKey::random(&mut OsRng);
        let attestation_cert = Self::generate_self_signed_cert(&attestation_key);

        let attestation_key_info = Info {
            object_id: DEFAULT_ATTESTATION_KEY_ID,
            object_type: Type::AsymmetricKey,
            algorithm: Algorithm::Asymmetric(asymmetric::Algorithm::EcP256),
            capabilities: Capability::SIGN_ATTESTATION_CERTIFICATE,
            delegated_capabilities: Capability::empty(),
            domains: Domain::all(),
            length: 0,
            sequence: 0,
            origin: Origin::Generated,
            label: "MOCKHSM ATTESTATION KEY".into(),
        };
        let attestation_cert_info = Info {
            object_id: DEFAULT_ATTESTATION_KEY_ID,
            object_type: Type::Opaque,
            algorithm: Algorithm::Opaque(opaque::Algorithm::X509Certificate),
            capabilities: Capability::GET_OPAQUE,
            delegated_capabilities: Capability::empty(),
            domains: Domain::all(),
            length: 0,
            sequence: 0,
            origin: Origin::Generated,
            label: "MOCKHSM ATTESTATION CERT".into(),
        };

        let attestation_cert_payload = Payload::Opaque(
            opaque::Algorithm::X509Certificate,
            attestation_cert.to_der().unwrap(),
        );
        let attestation_key_payload = Payload::EcdsaNistP256(attestation_key);

        let attestation_key_handle = Handle::new(DEFAULT_ATTESTATION_KEY_ID, Type::AsymmetricKey);
        let attestation_cert_handle = Handle::new(DEFAULT_ATTESTATION_KEY_ID, Type::Opaque);

        let _ = objects.insert(
            attestation_key_handle,
            Object {
                object_info: attestation_key_info,
                payload: attestation_key_payload,
            },
        );

        let _ = objects.insert(
            attestation_cert_handle,
            Object {
                object_info: attestation_cert_info,
                payload: attestation_cert_payload,
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

    /// Encrypt and serialize an object as ciphertext
    pub fn wrap_obj(
        &mut self,
        wrap_key_id: Id,
        object_id: Id,
        object_type: Type,
        nonce: &wrap::Nonce,
    ) -> Result<Vec<u8>, Error> {
        let wrap_key = self.get_wrap_key(wrap_key_id)?;

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
            alg_id: wrap_key.algorithm(),
            object_info: object_info.into(),
            data: object_to_wrap.payload.to_bytes(),
        })
        .unwrap();

        wrap_key
            .encrypt_in_place(nonce, b"", &mut wrapped_object)
            .unwrap();

        Ok(wrapped_object)
    }

    /// Deserialize an encrypted object and insert it into the HSM
    pub fn unwrap_obj<V: Into<Vec<u8>>>(
        &mut self,
        wrap_key_id: Id,
        nonce: &wrap::Nonce,
        ciphertext: V,
    ) -> Result<Handle, Error> {
        let wrap_key = self.get_wrap_key(wrap_key_id)?;
        let mut wrapped_data: Vec<u8> = ciphertext.into();
        wrap_key.decrypt_in_place(nonce, b"", &mut wrapped_data)?;

        let unwrapped_object: WrappedObject = deserialize(&wrapped_data).unwrap();

        let payload = match unwrapped_object.object_info.algorithm {
            Algorithm::Asymmetric(alg) if alg.is_rsa() => Payload::new(
                unwrapped_object.object_info.algorithm,
                // RSA encoding will include:
                //  - p
                //  - q
                //  - dp    -\
                //  - dq     +- internal state
                //  - qinv  -/
                //
                //  We can rebuild the key from the primes and we'll just discard the internal state here
                &unwrapped_object.data[..alg.key_len()],
            ),
            _ => Payload::new(
                unwrapped_object.object_info.algorithm,
                &unwrapped_object.data,
            ),
        };

        let object_key = Handle::new(
            unwrapped_object.object_info.object_id,
            unwrapped_object.object_info.object_type,
        );

        let object = Object {
            object_info: unwrapped_object.object_info.into(),
            payload,
        };

        assert!(self.0.insert(object_key.clone(), object).is_none());

        Ok(object_key)
    }

    /// Iterate over the objects
    pub fn iter(&self) -> Iter<'_> {
        self.0.iter()
    }

    /// Get a wrapping key
    fn get_wrap_key(&self, wrap_key_id: Id) -> Result<AesCcmKey, Error> {
        let wrap_key = match self.get(wrap_key_id, Type::WrapKey) {
            Some(k) => k,
            None => fail!(
                ErrorKind::ObjectNotFound,
                "no such wrap key: {:?}",
                wrap_key_id
            ),
        };

        match wrap_key.algorithm().wrap().unwrap() {
            wrap::Algorithm::Aes128Ccm => Ok(AesCcmKey::Aes128(
                Aes128Ccm::new_from_slice(&wrap_key.payload.to_bytes()).unwrap(),
            )),
            wrap::Algorithm::Aes192Ccm => Ok(AesCcmKey::Aes192(
                Aes192Ccm::new_from_slice(&wrap_key.payload.to_bytes()).unwrap(),
            )),
            wrap::Algorithm::Aes256Ccm => Ok(AesCcmKey::Aes256(
                Aes256Ccm::new_from_slice(&wrap_key.payload.to_bytes()).unwrap(),
            )),
        }
    }

    fn generate_self_signed_cert(secret_key: &p256::SecretKey) -> Certificate {
        struct SelfSigned;
        impl BuilderProfile for SelfSigned {
            fn get_issuer(&self, subject: &Name) -> Name {
                subject.clone()
            }
            fn get_subject(&self) -> Name {
                Name::from_str("CN=MockHSM Attestation").unwrap()
            }
            fn build_extensions(
                &self,
                _spk: SubjectPublicKeyInfoRef<'_>,
                _issuer_spk: SubjectPublicKeyInfoRef<'_>,
                _tbs: &TbsCertificate,
            ) -> builder::Result<Vec<Extension>> {
                Ok(vec![])
            }
        }

        let serial_number = serial_number::SerialNumber::generate(&mut OsRng).unwrap();
        let validity = Validity::new(
            // Yubico's Cert uses UTCTime for the not_before and GeneralizedTime for the not_after
            // (scheduled for 2071)
            Time::UtcTime(
                UtcTime::from_date_time(DateTime::new(2017, 1, 1, 0, 0, 0).unwrap()).unwrap(),
            ),
            Time::GeneralTime(GeneralizedTime::from_date_time(
                DateTime::new(2071, 10, 5, 0, 0, 0).unwrap(),
            )),
        );
        let pub_key = SubjectPublicKeyInfoOwned::from_key(&secret_key.public_key()).unwrap();

        let builder = CertificateBuilder::new(SelfSigned, serial_number, validity, pub_key)
            .expect("Create certificate builder");
        let signer = p256::ecdsa::SigningKey::from(secret_key);
        builder
            .build::<_, p256::ecdsa::DerSignature>(&signer)
            .unwrap()
    }
}

/// Iterator over objects
pub(crate) type Iter<'a> = MapIter<'a, Handle, Object>;
