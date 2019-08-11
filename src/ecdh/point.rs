use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// ECDH Public Keys (i.e. uncompressed public points)
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct UncompressedPoint(Vec<u8>);

impl UncompressedPoint {
    /// Create a `PublicKey` from an uncompressed public point.
    ///
    /// Point must be 57, 65, 97, 129 or 133 bytes
    pub fn from_bytes<B>(bytes: B) -> Option<Self>
    where
        B: Into<Vec<u8>>,
    {
        let bytes = bytes.into();

        match bytes.len() {
            57 | 65 | 97 | 129 | 133 => Some(UncompressedPoint(bytes)),
            _ => None,
        }
    }

    /// Borrow this SSH certificate as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for UncompressedPoint {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
