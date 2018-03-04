//! Authentication cryptograms (8-byte MACs) used for session verification

use std::fmt;

use clear_on_drop::clear::Clear;
use constant_time_eq::constant_time_eq;

/// Size of a cryptogram (i.e. truncated MAC)
pub const CRYPTOGRAM_SIZE: usize = 8;

/// Authentication cryptograms used to verify sessions
#[derive(Serialize, Deserialize, Eq)]
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "yubihsm_client::Cryptogram")
    }
}

impl PartialEq for Cryptogram {
    fn eq(&self, other: &Cryptogram) -> bool {
        constant_time_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl Drop for Cryptogram {
    fn drop(&mut self) {
        self.0.clear();
    }
}
