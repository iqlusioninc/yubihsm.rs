//! Object "payloads" in the MockHSM are instances of software implementations
//! of supported cryptographic primitives, already initialized with a private key

use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use untrusted;

use super::ecdsa::{ECDSAKeyPair, ECDSA_KEY_PAIR_SIZE};
use Algorithm;

/// Loaded instances of a cryptographic primitives in the MockHSM
pub(crate) enum Payload {
    /// ECDSA signing keys
    ECDSAKeyPair(ECDSAKeyPair),

    /// Ed25519 signing keys
    Ed25519KeyPair(Ed25519KeyPair),
}

/// Size of an Ed25519 key pair (in a YubiHSM)
pub(crate) const ED25519_KEY_PAIR_SIZE: u16 = 24;

impl Payload {
    /// Generate a new key with the given algorithm
    pub fn generate(algorithm: Algorithm) -> Self {
        let csprng = SystemRandom::new();

        match algorithm {
            Algorithm::EC_P256 => {
                let keypair = ECDSAKeyPair::generate(algorithm, &csprng);
                Payload::ECDSAKeyPair(keypair)
            }
            Algorithm::EC_ED25519 => {
                let pkcs8_key = Ed25519KeyPair::generate_pkcs8(&csprng).unwrap();
                let keypair =
                    Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_key)).unwrap();
                Payload::Ed25519KeyPair(keypair)
            }
            _ => panic!("MockHSM does not support this algorithm: {:?}", algorithm),
        }
    }

    /// Get the algorithm type for this payload
    pub fn algorithm(&self) -> Algorithm {
        match *self {
            Payload::ECDSAKeyPair(_) => Algorithm::EC_P256,
            Payload::Ed25519KeyPair(_) => Algorithm::EC_ED25519,
        }
    }

    /// Get the length of the object
    pub fn len(&self) -> u16 {
        match *self {
            Payload::ECDSAKeyPair(_) => ECDSA_KEY_PAIR_SIZE,
            Payload::Ed25519KeyPair(_) => ED25519_KEY_PAIR_SIZE,
        }
    }

    /// If this object is a public key, return its byte serialization
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        match *self {
            Payload::ECDSAKeyPair(ref k) => Some(k.public_key_bytes().into()),
            Payload::Ed25519KeyPair(ref k) => Some(k.public_key_bytes().into()),
        }
    }
}
