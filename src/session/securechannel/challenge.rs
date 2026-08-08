//! Challenge messages used as part of SCP03's challenge/response protocol.

use rand_core::Rng;
use serde::{Deserialize, Serialize};

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
        let mut rng = rand::rng();
        rng.fill_bytes(&mut challenge);
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
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Create a `Challenge` from externally supplied bytes, generating a random
    /// one if the input is empty.
    ///
    /// The empty case is not hypothetical: YubiKey firmware 5.4.3 returns an
    /// empty challenge, and the protocol still needs one. Callers holding a
    /// challenge from such a device pass its bytes through here.
    ///
    /// Returns an error if the input is neither empty nor exactly 8 bytes.
    pub fn from_slice_or_random(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }

        if bytes.len() != CHALLENGE_SIZE {
            fail!(
                ErrorKind::ProtocolError,
                "challenge must be {} bytes (got {})",
                CHALLENGE_SIZE,
                bytes.len()
            );
        }

        let mut challenge = [0u8; CHALLENGE_SIZE];
        challenge.copy_from_slice(bytes);
        Ok(Challenge(challenge))
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}
