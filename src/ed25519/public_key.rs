//! Ed25519 public keys

// TODO(tarcieri): move this upstream into the `ed25519` crate

use std::fmt::{self, Debug};

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create an Ed25519 public key from a 32-byte array
    pub fn new(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    /// Create an Ed25519 public key from its serialized (compressed Edwards-y) form
    pub fn from_bytes<B>(bytes: B) -> Option<Self>
    where
        B: AsRef<[u8]>,
    {
        if bytes.as_ref().len() == PUBLIC_KEY_SIZE {
            let mut public_key = [0u8; PUBLIC_KEY_SIZE];
            public_key.copy_from_slice(bytes.as_ref());
            Some(PublicKey(public_key))
        } else {
            None
        }
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519::PublicKey({:?})", self.as_ref())
    }
}
