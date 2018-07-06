//! ECDSA keypairs

use ring::rand::{SecureRandom, SystemRandom};

// TODO: ideally *ring* could do everything our `ECDSAKeyPair` type is doing.
// This is the biggest blocker: https://github.com/briansmith/ring/issues/672
use ring::signature::ECDSAKeyPair as ECDSAPrivateKey;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, Signature};
use untrusted;

use Algorithm;

/// Size of a NIST P-256 keypair
pub(crate) const ECDSA_KEY_PAIR_SIZE: u16 = 96;

/// Size of a raw NIST P-256 uncompressed public key (i.e. sans DER OCTET STRING tag)
pub(crate) const ECDSA_PUBLIC_KEY_SIZE: usize = 64;

/// ECDSA keypairs (TODO: use upstream *ring* functionality for this when it becomes available)
pub(crate) struct ECDSAKeyPair {
    /// *ring* ECDSA private key type
    private_key: ECDSAPrivateKey,

    /// Public key bytes
    public_key_bytes: Vec<u8>,
}

impl ECDSAKeyPair {
    /// Generate a new ECDSA keypair
    pub fn generate(algorithm: Algorithm, csprng: &SecureRandom) -> Self {
        let algorithm = match algorithm {
            Algorithm::EC_P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            _ => panic!("unsupported ECDSA algorithm: {:?}", algorithm),
        };

        let pkcs8_key = ECDSAPrivateKey::generate_pkcs8(algorithm, csprng).unwrap();
        let pkcs8_key_len = pkcs8_key.as_ref().len();

        let private_key =
            ECDSAPrivateKey::from_pkcs8(algorithm, untrusted::Input::from(pkcs8_key.as_ref()))
                .unwrap();

        let public_key_bytes =
            Vec::from(&pkcs8_key.as_ref()[(pkcs8_key_len - ECDSA_PUBLIC_KEY_SIZE)..]);

        Self {
            private_key,
            public_key_bytes,
        }
    }

    /// Obtain the public key bytes for this keypair
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key_bytes.as_ref()
    }

    /// Sign a message with this key, returning an ASN.1 DER encoded signature
    pub fn sign<T: AsRef<[u8]>>(&self, message: T) -> Signature {
        self.private_key
            .sign(
                untrusted::Input::from(message.as_ref()),
                &SystemRandom::new(),
            )
            .unwrap()
    }
}
