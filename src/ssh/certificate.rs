use serde::{Deserialize, Serialize};

/// SSH certificate
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Certificate(Vec<u8>);

impl Certificate {
    /// Create an SSH certificate from serialized bytes
    pub fn from_bytes<B>(bytes: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Certificate(bytes.into())
    }

    /// Borrow this SSH certificate as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
