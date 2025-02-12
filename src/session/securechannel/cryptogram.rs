//! Authentication cryptograms (8-byte MACs) used for session verification

use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Size of a cryptogram (i.e. truncated MAC)
pub const CRYPTOGRAM_SIZE: usize = 8;

/// Authentication cryptograms used to verify sessions
#[derive(Clone, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct Cryptogram([u8; CRYPTOGRAM_SIZE]);

impl Cryptogram {
    /// Create a new cryptogram from a slice
    ///
    /// Panics if the slice is not 8-bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 8, "cryptogram must be 8-bytes long");

        let mut cryptogram = [0u8; CRYPTOGRAM_SIZE];
        cryptogram.copy_from_slice(slice);
        Cryptogram(cryptogram)
    }

    /// Borrow the cryptogram value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Cryptogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(f, "yubihsm::Cryptogram(...)")
    }
}

impl ConstantTimeEq for Cryptogram {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
