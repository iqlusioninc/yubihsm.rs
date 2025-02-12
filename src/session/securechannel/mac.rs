//! Truncated Message Authentication Codes (MACs) used by SCP03
//!
//! The CMAC (Cipher-based MAC) function is used, and ordinarily would have a
//! 16-byte tag, but SCP03 truncates it to 8-bytes. This makes implementations
//! potentially much more vulnerable to online attacks, and significantly
//! increases the chance of collisions since the birthday bound is much
//! lower (~2^32 messages).

use crate::session;
use cmac::digest::array::{typenum::U16, Array};
use std::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Message Authentication Codes used to verify messages
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Mac([u8; Self::BYTE_SIZE]);

impl Mac {
    /// Size of the MAC in bytes: SCP03 truncates it to 8-bytes
    pub const BYTE_SIZE: usize = 8;

    /// Create a new MAC tag from a slice
    ///
    /// Panics if the slice is not 8-bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 8, "MAC must be 8-bytes long");

        let mut mac = [0u8; Self::BYTE_SIZE];
        mac.copy_from_slice(slice);
        Mac(mac)
    }

    /// Borrow the MAC value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Verify a 16-byte Array against this MAC tag
    pub fn verify<M>(&self, other: M) -> Result<(), session::Error>
    where
        M: Into<Mac>,
    {
        if self.ct_eq(&other.into()).unwrap_u8() == 1 {
            Ok(())
        } else {
            fail!(session::ErrorKind::VerifyFailed, "MAC mismatch!");
        }
    }
}

impl ConstantTimeEq for Mac {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(f, "yubihsm::Mac")
    }
}

impl<'a> From<&'a Array<u8, U16>> for Mac {
    fn from(array: &'a Array<u8, U16>) -> Self {
        Self::from_slice(&array.as_slice()[..Self::BYTE_SIZE])
    }
}
