//! Wrap messages

use super::nonce::{self, Nonce};
use super::{Error, ErrorKind};
use anomaly::fail;
use serde::{Deserialize, Serialize};

/// Wrap wessage (encrypted HSM object or arbitrary data) encrypted under a wrap key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    /// Nonce used to encrypt the wrapped data
    pub nonce: Nonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Load a `Message` from a byte vector
    pub fn from_vec(mut vec: Vec<u8>) -> Result<Self, Error> {
        if vec.len() < nonce::SIZE {
            fail!(
                ErrorKind::LengthInvalid,
                "message must be at least {}-bytes",
                nonce::SIZE
            );
        }

        let ciphertext = vec.split_off(nonce::SIZE);
        let nonce = vec.as_ref();

        Ok(Self::new(nonce, ciphertext))
    }

    /// Create a new `Message`
    pub fn new<N, V>(nonce: N, ciphertext: V) -> Self
    where
        N: Into<Nonce>,
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

impl Into<Vec<u8>> for Message {
    fn into(self) -> Vec<u8> {
        let Message {
            nonce,
            mut ciphertext,
        } = self;

        let mut vec = Vec::with_capacity(nonce::SIZE + ciphertext.len());
        vec.extend_from_slice(nonce.as_ref());
        vec.append(&mut ciphertext);
        vec
    }
}
