//! Truncated Message Authentication Codes (MACs) used by SCP03
//!
//! The CMAC (Cipher-based MAC) function is used, and ordinarily would have a
//! 16-byte tag, but SCP03 truncates it to 8-bytes. This makes implementations
//! potentially much more vulnerable to online attacks, and significantly
//! increases the chance of collisions since the birthday bound is much
//! lower (~2^32 messages).

use clear_on_drop::clear::Clear;
use cmac::crypto_mac::generic_array::typenum::U16;
use cmac::crypto_mac::generic_array::GenericArray;
use std::fmt;
use subtle::{Choice, ConstantTimeEq};

use super::SecureChannelError;

/// Size of the MAC in bytes: SCP03 truncates it to 8-bytes
pub const MAC_SIZE: usize = 8;

/// Message Authentication Codes used to verify messages
pub struct Mac([u8; MAC_SIZE]);

impl Mac {
    /// Create a new MAC tag from a slice
    ///
    /// Panics if the slice is not 8-bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 8, "MAC must be 8-bytes long");

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(slice);
        Mac(mac)
    }

    /// Borrow the MAC value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Verify a 16-byte GenericArray against this MAC tag
    pub fn verify<M>(&self, other: M) -> Result<(), SecureChannelError>
    where
        M: Into<Mac>,
    {
        if self.ct_eq(&other.into()).unwrap_u8() == 1 {
            Ok(())
        } else {
            secure_channel_fail!(VerifyFailed, "MAC mismatch!");
        }
    }
}

impl ConstantTimeEq for Mac {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_ref().ct_eq(other.0.as_ref())
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(f, "yubihsm::Mac")
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<'a> From<&'a GenericArray<u8, U16>> for Mac {
    fn from(array: &'a GenericArray<u8, U16>) -> Self {
        Self::from_slice(&array.as_slice()[..MAC_SIZE])
    }
}
