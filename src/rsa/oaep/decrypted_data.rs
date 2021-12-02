//! RSA OAEP decrypted data

use serde::{Deserialize, Serialize};

/// RSA OAEP decrypted data
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecryptedData(pub Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl DecryptedData {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the signature
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for DecryptedData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for DecryptedData {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
