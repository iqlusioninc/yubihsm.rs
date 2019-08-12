//! Object "payloads" in the MockHsm are instances of software implementations
//! of supported cryptographic primitives, already initialized with a private key

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};

use crate::{algorithm::Algorithm, asymmetric, authentication, hmac, opaque, wrap};

/// Size of an Ed25519 seed
pub(crate) const ED25519_SEED_SIZE: usize = 32;

/// Loaded instances of a cryptographic primitives in the MockHsm
#[derive(Debug)]
pub(crate) enum Payload {
    /// Authentication keys
    AuthenticationKey(authentication::Key),

    /// Ed25519 signing keys
    Ed25519KeyPair([u8; ED25519_SEED_SIZE]),

    /// HMAC key
    HmacKey(hmac::Algorithm, Vec<u8>),

    /// Opaque data
    Opaque(opaque::Algorithm, Vec<u8>),

    /// Wrapping (i.e. symmetric encryption keys)
    // TODO: actually simulate AES-CCM. Instead we use GCM because *ring* has it
    WrapKey(wrap::Algorithm, Vec<u8>),
}

impl Payload {
    /// Create a new payload from the given algorithm and data
    pub fn new(algorithm: Algorithm, data: &[u8]) -> Self {
        match algorithm {
            Algorithm::Wrap(alg) => Payload::WrapKey(alg, data.into()),
            Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519) => {
                assert_eq!(data.len(), ED25519_SEED_SIZE);
                let mut bytes = [0u8; ED25519_SEED_SIZE];
                bytes.copy_from_slice(data);
                Payload::Ed25519KeyPair(bytes)
            }
            Algorithm::Hmac(alg) => Payload::HmacKey(alg, data.into()),
            Algorithm::Opaque(alg) => Payload::Opaque(alg, data.into()),
            Algorithm::Authentication(_) => {
                Payload::AuthenticationKey(authentication::Key::from_slice(data).unwrap())
            }
            _ => panic!("MockHsm does not support putting {:?} objects", algorithm),
        }
    }

    /// Generate a new key with the given algorithm
    pub fn generate(algorithm: Algorithm) -> Self {
        let csprng = SystemRandom::new();

        match algorithm {
            Algorithm::Wrap(wrap_alg) => {
                let mut bytes = vec![0u8; wrap_alg.key_len()];
                csprng.fill(&mut bytes).unwrap();
                Payload::WrapKey(wrap_alg, bytes)
            }
            Algorithm::Asymmetric(asymmetric_alg) => match asymmetric_alg {
                asymmetric::Algorithm::Ed25519 => {
                    let mut bytes = [0u8; ED25519_SEED_SIZE];
                    csprng.fill(&mut bytes).unwrap();
                    Payload::Ed25519KeyPair(bytes)
                }
                _ => panic!(
                    "MockHsm doesn't support this asymmetric algorithm: {:?}",
                    asymmetric_alg
                ),
            },
            Algorithm::Hmac(hmac_alg) => {
                let mut bytes = vec![0u8; hmac_alg.key_len()];
                csprng.fill(&mut bytes).unwrap();
                Payload::HmacKey(hmac_alg, bytes)
            }
            _ => panic!(
                "MockHsm does not support generating {:?} objects",
                algorithm
            ),
        }
    }

    /// Get the algorithm type for this payload
    pub fn algorithm(&self) -> Algorithm {
        match *self {
            Payload::AuthenticationKey(_) => {
                Algorithm::Authentication(authentication::Algorithm::YubicoAes)
            }
            Payload::Ed25519KeyPair(_) => Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519),
            Payload::HmacKey(alg, _) => alg.into(),
            Payload::Opaque(alg, _) => alg.into(),
            Payload::WrapKey(alg, _) => alg.into(),
        }
    }

    /// Get the length of the object
    pub fn len(&self) -> u16 {
        let l = match *self {
            Payload::AuthenticationKey(_) => authentication::key::SIZE,
            Payload::Ed25519KeyPair(_) => ED25519_SEED_SIZE,
            Payload::HmacKey(_, ref data) => data.len(),
            Payload::Opaque(_, ref data) => data.len(),
            Payload::WrapKey(_, ref data) => data.len(),
        };
        l as u16
    }

    /// If this object is a public key, return its byte serialization
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        match *self {
            Payload::Ed25519KeyPair(ref k) => Some(
                Ed25519KeyPair::from_seed_unchecked(k)
                    .unwrap()
                    .public_key()
                    .as_ref()
                    .into(),
            ),
            _ => None,
        }
    }

    /// If this payload is an auth key, return a reference to it
    pub fn authentication_key(&self) -> Option<&authentication::Key> {
        match *self {
            Payload::AuthenticationKey(ref k) => Some(k),
            _ => None,
        }
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Payload::AuthenticationKey(ref k) => k.0.as_ref(),
            Payload::Ed25519KeyPair(ref k) => k.as_ref(),
            Payload::HmacKey(_, ref data) => data,
            Payload::Opaque(_, ref data) => data,
            Payload::WrapKey(_, ref data) => data,
        }
    }
}
