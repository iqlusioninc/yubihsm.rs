//! ECDSA keypairs

use ring::rand::{SecureRandom, SystemRandom};

// TODO: ideally *ring* could do everything our `ECDSAKeyPair` type is doing.
// This is the biggest blocker: https://github.com/briansmith/ring/issues/672
use ring::signature::ECDSAKeyPair as ECDSAPrivateKey;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, Signature};
use untrusted;

use AsymmetricAlgorithm;

/// Size of a NIST P-256 keypair
pub(crate) const ECDSA_KEY_PAIR_SIZE: usize = 96;

/// Size of a raw NIST P-256 uncompressed public key (i.e. sans DER OCTET STRING tag)
pub(crate) const ECDSA_PUBLIC_KEY_SIZE: usize = 64;

/// ECDSA keypairs (TODO: use upstream *ring* functionality for this when it becomes available)
pub(crate) struct ECDSAKeyPair {
    /// *ring* SigningAlgorithm
    pub algorithm: AsymmetricAlgorithm,

    /// PKCS#8 private key
    pub private_key_bytes: Vec<u8>,

    /// Public key bytes
    pub public_key_bytes: Vec<u8>,
}

impl ECDSAKeyPair {
    /// Generate a new ECDSA keypair
    pub fn generate(algorithm: AsymmetricAlgorithm, csprng: &SecureRandom) -> Self {
        let signing_algorithm = match algorithm {
            AsymmetricAlgorithm::EC_P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            _ => panic!("unsupported ECDSA algorithm: {:?}", algorithm),
        };

        let private_key_bytes = Vec::from(
            ECDSAPrivateKey::generate_pkcs8(signing_algorithm, csprng)
                .unwrap()
                .as_ref(),
        );
        let private_key_len = private_key_bytes.len();

        let public_key_bytes =
            Vec::from(&private_key_bytes[(private_key_len - ECDSA_PUBLIC_KEY_SIZE)..]);

        Self {
            algorithm,
            private_key_bytes,
            public_key_bytes,
        }
    }

    /// Sign a message with this key, returning an ASN.1 DER encoded signature
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        let signing_algorithm = match self.algorithm {
            AsymmetricAlgorithm::EC_P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            _ => panic!("unsupported ECDSA algorithm: {:?}", self.algorithm),
        };

        let private_key = ECDSAPrivateKey::from_pkcs8(
            signing_algorithm,
            untrusted::Input::from(&self.private_key_bytes),
        ).unwrap();

        private_key
            .sign(
                untrusted::Input::from(message.as_ref()),
                &SystemRandom::new(),
            )
            .unwrap()
    }
}
