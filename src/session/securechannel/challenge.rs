//! Challenge messages used as part of SCP03's challenge/response protocol.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[cfg(feature = "yubihsm-auth")]
use crate::session::error::{Error, ErrorKind};

/// Size of a challenge message
pub const CHALLENGE_SIZE: usize = 8;

/// A challenge message, sent by either host or the card
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Challenge([u8; CHALLENGE_SIZE]);

impl Challenge {
    /// Create a new random `Challenge`
    pub fn new() -> Self {
        let mut challenge = [0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut challenge);
        Challenge(challenge)
    }

    /// Create a new challenge from a slice
    ///
    /// Panics if the slice is not 8-bytes
    #[cfg(all(test, feature = "mockhsm"))]
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 8, "challenge must be 8-bytes long");

        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge.copy_from_slice(slice);
        Challenge(challenge)
    }

    /// Borrow the challenge value as a slice
    #[cfg_attr(clippy, allow(clippy::trivially_copy_pass_by_ref))]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Creates `Challenge` from a `yubikey::hsmauth::Challenge`.
    ///
    /// `YubiKey` firmware 5.4.3 will generate an empty challenge, this will
    /// generate one from RNG if we're provided an empty challenge
    // Note(baloo): because of the side-effect described above, this is not
    // made a regular From<yubikey::hsmauth::Challenge>.
    #[cfg(feature = "yubihsm-auth")]
    pub fn from_yubikey_challenge(yc: yubikey::hsmauth::Challenge) -> Self {
        if yc.is_empty() {
            Self::new()
        } else {
            let mut challenge = [0u8; CHALLENGE_SIZE];
            challenge.copy_from_slice(yc.as_slice());
            Challenge(challenge)
        }
    }
}

#[cfg(feature = "yubihsm-auth")]
impl TryFrom<Challenge> for yubikey::hsmauth::Challenge {
    type Error = Error;

    fn try_from(c: Challenge) -> Result<Self, Error> {
        let mut challenge = yubikey::hsmauth::Challenge::default();
        challenge
            .copy_from_slice(c.as_slice())
            .map_err(|e| Error::from(ErrorKind::ProtocolError.context(e)))?;

        Ok(challenge)
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}
