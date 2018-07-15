//! Object "payloads" in the MockHSM are instances of software implementations
//! of supported cryptographic primitives, already initialized with a private key

use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::Ed25519KeyPair;
use untrusted;

use super::ecdsa::{ECDSAKeyPair, ECDSA_KEY_PAIR_SIZE};
use algorithm::{Algorithm, AsymmetricAlgorithm, HMACAlgorithm, OpaqueAlgorithm, WrapAlgorithm};
use auth_key::{AuthKey, AUTH_KEY_SIZE};

/// Size of an Ed25519 seed
pub(crate) const ED25519_SEED_SIZE: usize = 32;

/// Loaded instances of a cryptographic primitives in the MockHSM
pub(crate) enum Payload {
    /// Authentication keys
    AuthKey(AuthKey),

    /// ECDSA signing keys
    ECDSAKeyPair(ECDSAKeyPair),

    /// Ed25519 signing keys
    Ed25519KeyPair([u8; ED25519_SEED_SIZE]),

    /// HMAC key
    HMACKey(HMACAlgorithm, Vec<u8>),

    /// Opaque data
    Opaque(OpaqueAlgorithm, Vec<u8>),

    /// Wrapping (i.e. symmetric encryption keys)
    // TODO: actually simulate AES-CCM. Instead we use GCM because *ring* has it
    WrapKey(WrapAlgorithm, Vec<u8>),
}

impl Payload {
    /// Create a new payload from the given algorithm and data
    pub fn new(algorithm: Algorithm, data: &[u8]) -> Self {
        match algorithm {
            Algorithm::AES128_CCM_WRAP | Algorithm::AES256_CCM_WRAP => Payload::WrapKey(
                WrapAlgorithm::from_algorithm(algorithm).unwrap(),
                data.into(),
            ),
            Algorithm::AES192_CCM_WRAP => panic!("friends don't let friends use AES-192"),
            Algorithm::EC_ED25519 => {
                assert_eq!(data.len(), ED25519_SEED_SIZE);
                let mut bytes = [0u8; ED25519_SEED_SIZE];
                bytes.copy_from_slice(data);
                Payload::Ed25519KeyPair(bytes)
            }
            Algorithm::HMAC_SHA1
            | Algorithm::HMAC_SHA256
            | Algorithm::HMAC_SHA384
            | Algorithm::HMAC_SHA512 => Payload::HMACKey(
                HMACAlgorithm::from_algorithm(algorithm).unwrap(),
                data.into(),
            ),
            Algorithm::OPAQUE_DATA | Algorithm::OPAQUE_X509_CERT => Payload::Opaque(
                OpaqueAlgorithm::from_algorithm(algorithm).unwrap(),
                data.into(),
            ),
            Algorithm::YUBICO_AES_AUTH => Payload::AuthKey(AuthKey::from_slice(data).unwrap()),
            _ => panic!("MockHSM does not support putting {:?} objects", algorithm),
        }
    }

    /// Generate a new key with the given algorithm
    pub fn generate(algorithm: Algorithm) -> Self {
        let csprng = SystemRandom::new();

        match algorithm {
            Algorithm::AES128_CCM_WRAP | Algorithm::AES256_CCM_WRAP => {
                let wrap_alg = WrapAlgorithm::from_algorithm(algorithm).unwrap();
                let mut bytes = vec![0u8; wrap_alg.key_len()];
                csprng.fill(&mut bytes).unwrap();
                Payload::WrapKey(wrap_alg, bytes)
            }
            Algorithm::EC_P256 => {
                let keypair = ECDSAKeyPair::generate(
                    AsymmetricAlgorithm::from_algorithm(algorithm).unwrap(),
                    &csprng,
                );
                Payload::ECDSAKeyPair(keypair)
            }
            Algorithm::EC_ED25519 => {
                let mut bytes = [0u8; ED25519_SEED_SIZE];
                csprng.fill(&mut bytes).unwrap();
                Payload::Ed25519KeyPair(bytes)
            }
            Algorithm::HMAC_SHA1
            | Algorithm::HMAC_SHA256
            | Algorithm::HMAC_SHA384
            | Algorithm::HMAC_SHA512 => {
                let hmac_alg = HMACAlgorithm::from_algorithm(algorithm).unwrap();
                let mut bytes = vec![0u8; hmac_alg.key_len()];
                csprng.fill(&mut bytes).unwrap();
                Payload::HMACKey(hmac_alg, bytes)
            }
            _ => panic!(
                "MockHSM does not support generating {:?} objects",
                algorithm
            ),
        }
    }

    /// Get the algorithm type for this payload
    pub fn algorithm(&self) -> Algorithm {
        match *self {
            Payload::AuthKey(_) => Algorithm::YUBICO_AES_AUTH,
            Payload::ECDSAKeyPair(_) => Algorithm::EC_P256,
            Payload::Ed25519KeyPair(_) => Algorithm::EC_ED25519,
            Payload::HMACKey(alg, _) => alg.into(),
            Payload::Opaque(alg, _) => alg.into(),
            Payload::WrapKey(alg, _) => alg.into(),
        }
    }

    /// Get the length of the object
    pub fn len(&self) -> u16 {
        let l = match *self {
            Payload::AuthKey(_) => AUTH_KEY_SIZE,
            Payload::ECDSAKeyPair(_) => ECDSA_KEY_PAIR_SIZE,
            Payload::Ed25519KeyPair(_) => ED25519_SEED_SIZE,
            Payload::HMACKey(_, ref data) => data.len(),
            Payload::Opaque(_, ref data) => data.len(),
            Payload::WrapKey(_, ref data) => data.len(),
        };
        l as u16
    }

    /// If this object is a public key, return its byte serialization
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        match *self {
            Payload::ECDSAKeyPair(ref k) => Some(k.public_key_bytes.clone()),
            Payload::Ed25519KeyPair(ref k) => Some(
                Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(k))
                    .unwrap()
                    .public_key_bytes()
                    .into(),
            ),
            _ => None,
        }
    }

    /// If this payload is an auth key, return a reference to it
    pub fn auth_key(&self) -> Option<&AuthKey> {
        match *self {
            Payload::AuthKey(ref k) => Some(k),
            _ => None,
        }
    }
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        match *self {
            Payload::AuthKey(ref k) => k.0.as_ref(),
            Payload::ECDSAKeyPair(ref k) => &k.private_key_bytes,
            Payload::Ed25519KeyPair(ref k) => k.as_ref(),
            Payload::HMACKey(_, ref data) => data,
            Payload::Opaque(_, ref data) => data,
            Payload::WrapKey(_, ref data) => data,
        }
    }
}
