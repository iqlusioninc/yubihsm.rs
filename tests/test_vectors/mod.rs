//! Cryptographic test vectors for use in integration tests

/// AES-CCM (Counter with CBC-MAC) test vectors
mod aesccm;

/// Ed25519 digital signature test vectors
mod ed25519;

pub use self::aesccm::AESCCM_TEST_VECTORS;
pub use self::ed25519::ED25519_TEST_VECTORS;

/// Authenticated encryption test vector (presently specialized for AES-CCM)
pub struct EncryptionTestVector {
    /// Encryption key
    pub key: &'static [u8],

    /// Nonce the given message is encrypted under
    pub nonce: &'static [u8],

    /// Length of the plaintext part of an AES-CCM packet
    pub ptlen: usize,

    /// Plaintext to be encrypted
    pub plaintext: &'static [u8],

    /// Resulting ciphertext after encryption
    pub ciphertext: &'static [u8],
}

/// Signature test vector
pub struct SignatureTestVector {
    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],
}
