//! Object "payloads" in the MockHsm are instances of software implementations
//! of supported cryptographic primitives, already initialized with a private key

use crate::{algorithm::Algorithm, asymmetric, authentication, hmac, opaque, wrap};
use ed25519_dalek as ed25519;
use rand_core::{OsRng, RngCore};

/// Loaded instances of a cryptographic primitives in the MockHsm
#[derive(Debug)]
pub(crate) enum Payload {
    /// Authentication key
    AuthenticationKey(authentication::Key),

    /// ECDSA/P-256 signing key
    EcdsaNistP256(p256::SecretKey),

    /// ECDSA/secp256k1 signing key,
    EcdsaSecp256k1(k256::SecretKey),

    /// Ed25519 signing key
    Ed25519Key(ed25519::SecretKey),

    /// HMAC key
    HmacKey(hmac::Algorithm, Vec<u8>),

    /// Opaque data
    Opaque(opaque::Algorithm, Vec<u8>),

    /// Wrapping (i.e. symmetric encryption keys)
    WrapKey(wrap::Algorithm, Vec<u8>),
}

impl Payload {
    /// Create a new payload from the given algorithm and data
    pub fn new(algorithm: Algorithm, data: &[u8]) -> Self {
        match algorithm {
            Algorithm::Wrap(alg) => Payload::WrapKey(alg, data.into()),
            Algorithm::Asymmetric(asymmetric_alg) => match asymmetric_alg {
                asymmetric::Algorithm::EcP256 => {
                    assert_eq!(data.len(), 32);
                    Payload::EcdsaNistP256(p256::SecretKey::from_bytes(data).unwrap())
                }
                asymmetric::Algorithm::EcK256 => {
                    assert_eq!(data.len(), 32);
                    Payload::EcdsaSecp256k1(k256::SecretKey::from_bytes(data).unwrap())
                }
                asymmetric::Algorithm::Ed25519 => {
                    assert_eq!(data.len(), ed25519::SECRET_KEY_LENGTH);
                    Payload::Ed25519Key(ed25519::SecretKey::from_bytes(data).unwrap())
                }
                _ => panic!(
                    "MockHsm doesn't support this asymmetric algorithm: {:?}",
                    asymmetric_alg
                ),
            },
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
        match algorithm {
            Algorithm::Wrap(wrap_alg) => {
                let mut bytes = vec![0u8; wrap_alg.key_len()];
                OsRng.fill_bytes(&mut bytes);
                Payload::WrapKey(wrap_alg, bytes)
            }
            Algorithm::Asymmetric(asymmetric_alg) => match asymmetric_alg {
                asymmetric::Algorithm::EcP256 => {
                    Payload::EcdsaNistP256(p256::SecretKey::random(&mut OsRng))
                }
                asymmetric::Algorithm::EcK256 => {
                    Payload::EcdsaSecp256k1(k256::SecretKey::random(&mut OsRng))
                }
                asymmetric::Algorithm::Ed25519 => {
                    let mut sk = [0u8; 32];
                    OsRng.fill_bytes(&mut sk);
                    Payload::Ed25519Key(
                        ed25519::SecretKey::from_bytes(&sk).expect("Ed25519 keygen failure"),
                    )
                }
                _ => panic!(
                    "MockHsm doesn't support this asymmetric algorithm: {:?}",
                    asymmetric_alg
                ),
            },
            Algorithm::Hmac(hmac_alg) => {
                let mut bytes = vec![0u8; hmac_alg.key_len()];
                OsRng.fill_bytes(&mut bytes);
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
            Payload::EcdsaNistP256(_) => Algorithm::Asymmetric(asymmetric::Algorithm::EcP256),
            Payload::EcdsaSecp256k1(_) => Algorithm::Asymmetric(asymmetric::Algorithm::EcK256),
            Payload::Ed25519Key(_) => Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519),
            Payload::HmacKey(alg, _) => alg.into(),
            Payload::Opaque(alg, _) => alg.into(),
            Payload::WrapKey(alg, _) => alg.into(),
        }
    }

    /// Get the length of the object
    pub fn len(&self) -> u16 {
        let l = match self {
            Payload::AuthenticationKey(_) => authentication::key::SIZE,
            Payload::EcdsaNistP256(_) | Payload::EcdsaSecp256k1(_) => 32,
            Payload::Ed25519Key(_) => ed25519::SECRET_KEY_LENGTH,
            Payload::HmacKey(_, ref data) => data.len(),
            Payload::Opaque(_, ref data) => data.len(),
            Payload::WrapKey(_, ref data) => data.len(),
        };
        l as u16
    }

    /// If this object is a public key, return its byte serialization
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Payload::EcdsaNistP256(secret_key) => {
                p256::EncodedPoint::from_secret_key(secret_key, false)
                    .to_untagged_bytes()
                    .map(|b| b.to_vec())
            }
            Payload::EcdsaSecp256k1(secret_key) => {
                k256::EncodedPoint::from_secret_key(secret_key, false)
                    .to_untagged_bytes()
                    .map(|b| b.to_vec())
            }
            Payload::Ed25519Key(secret_key) => {
                Some(ed25519::PublicKey::from(secret_key).as_ref().into())
            }
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

    /// Serialize this payload as a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Payload::AuthenticationKey(k) => k.0.as_ref().into(),
            Payload::EcdsaNistP256(k) => k.to_bytes().to_vec(),
            Payload::EcdsaSecp256k1(k) => k.to_bytes().to_vec(),
            Payload::Ed25519Key(k) => k.as_ref().into(),
            Payload::HmacKey(_, data) => data.clone(),
            Payload::Opaque(_, data) => data.clone(),
            Payload::WrapKey(_, data) => data.clone(),
        }
    }
}
