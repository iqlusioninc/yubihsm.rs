use failure::Error;
#[cfg(feature = "mockhsm")]
use rand::{OsRng, RngCore};
use std::fmt;

/// Number of bytes in a nonce used for "wrapping" (i.e AES-CCM encryption)
pub const WRAP_NONCE_SIZE: usize = 13;

/// Message (either object or arbitrary data) encrypted under a wrap key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WrapMessage {
    /// Nonce used to encrypt the wrapped data
    pub nonce: WrapNonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: Vec<u8>,
}

impl WrapMessage {
    /// Load a `WrapMessage` from a byte vector
    pub fn from_vec(mut vec: Vec<u8>) -> Result<Self, Error> {
        if vec.len() < WRAP_NONCE_SIZE {
            bail!("message must be at least {}-bytes", WRAP_NONCE_SIZE);
        }

        let mut nonce = [0u8; WRAP_NONCE_SIZE];
        nonce.copy_from_slice(vec.split_off(WRAP_NONCE_SIZE).as_ref());

        Ok(Self::new(nonce, vec))
    }

    /// Create a new `WrapMessage`
    pub fn new<N, V>(nonce: N, ciphertext: V) -> Self
    where
        N: Into<WrapNonce>,
        V: Into<Vec<u8>>,
    {
        Self {
            nonce: nonce.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// Convert this message into a byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl Into<Vec<u8>> for WrapMessage {
    fn into(self) -> Vec<u8> {
        let WrapMessage {
            nonce,
            mut ciphertext,
        } = self;

        let mut vec = Vec::with_capacity(WRAP_NONCE_SIZE + ciphertext.len());
        vec.extend_from_slice(nonce.as_ref());
        vec.append(&mut ciphertext);

        vec
    }
}

/// Nonces for AES-CCM keywrapping
#[derive(Debug, Clone)]
pub struct WrapNonce(pub [u8; WRAP_NONCE_SIZE]);

impl WrapNonce {
    /// Generate a random `WrapNonce`
    #[cfg(feature = "mockhsm")]
    pub fn generate() -> Self {
        let mut rand = OsRng::new().unwrap();
        let mut bytes = [0u8; WRAP_NONCE_SIZE];
        rand.fill_bytes(&mut bytes);
        WrapNonce(bytes)
    }
}

impl AsRef<[u8]> for WrapNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; WRAP_NONCE_SIZE]> for WrapNonce {
    fn from(bytes: [u8; WRAP_NONCE_SIZE]) -> WrapNonce {
        WrapNonce(bytes)
    }
}

impl_array_serializers!(WrapNonce, WRAP_NONCE_SIZE);
