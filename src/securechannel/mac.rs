//! Truncated Message Authentication Codes (MACs) used by SCP03
//!
//! The CMAC (Cipher-based MAC) function is used, and ordinarily would have a
//! 16-byte tag, but SCP03 truncates it to 8-bytes. This makes implementations
//! potentially much more vulnerable to online attacks, and significantly
//! increases the chance of collisions since the birthday bound is much
//! lower (~2^32 messages).

use clear_on_drop::clear::Clear;
#[cfg(feature = "mockhsm")]
use cmac::crypto_mac::MacResult;
#[cfg(feature = "mockhsm")]
use cmac::crypto_mac::generic_array::typenum::U16;
use constant_time_eq::constant_time_eq;
#[cfg(feature = "mockhsm")]
use failure::Error;

#[cfg(feature = "mockhsm")]
use super::SecureChannelError;

/// Size of the MAC in bytes: SCP03 truncates it to 8-bytes
pub const MAC_SIZE: usize = 8;

/// Message Authentication Codes used to verify messages
#[derive(Eq)]
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

    /// Verify a crypto_mac::MacResult against this MAC tag
    #[cfg(feature = "mockhsm")]
    pub fn verify(
        &self,
        crypto_mac: MacResult<U16>,
        chaining_value: &mut [u8],
    ) -> Result<(), Error> {
        let crypto_mac_code = crypto_mac.code();

        if !constant_time_eq(&self.0, &crypto_mac_code.as_slice()[..MAC_SIZE]) {
            Err(SecureChannelError::VerifyFailed {
                description: "MAC verification failure!".to_owned(),
            })?;
        }

        chaining_value.copy_from_slice(crypto_mac_code.as_slice());
        Ok(())
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Mac) -> bool {
        constant_time_eq(&self.0[..], &other.0[..])
    }
}

impl Drop for Mac {
    fn drop(&mut self) {
        self.0.clear();
    }
}
