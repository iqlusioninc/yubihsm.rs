//! Challenge messages used as part of SCP03's challenge/response protocol.

use getrandom::getrandom;
use serde::{Deserialize, Serialize};

/// Size of a challenge message
pub const CHALLENGE_SIZE: usize = 8;

/// A challenge message, sent by either host or the card
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Challenge([u8; CHALLENGE_SIZE]);

impl Challenge {
    /// Create a new random `Challenge`
    pub fn new() -> Self {
        let mut challenge = [0u8; CHALLENGE_SIZE];
        getrandom(&mut challenge).expect("RNG failure!");
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
}
