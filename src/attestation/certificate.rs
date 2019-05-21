use serde::{Deserialize, Serialize};

/// Attestation certificates (DER encoded X.509)
#[derive(Serialize, Deserialize, Debug)]
pub struct Certificate(pub Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl Certificate {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Get length of the certificate
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for Certificate {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
