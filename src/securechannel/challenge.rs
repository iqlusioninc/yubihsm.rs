use rand::{CryptoRng, OsRng, RngCore};

/// Size of a challenge message
pub const CHALLENGE_SIZE: usize = 8;

/// A challenge message, sent by either host or the card
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Challenge([u8; CHALLENGE_SIZE]);

impl Challenge {
    /// Generate a random Challenge using OsRng
    pub fn random() -> Self {
        Self::new(&mut OsRng::new().expect("RNG failure!"))
    }

    /// Create a new Challenge using the given RNG
    pub fn new<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut challenge = [0u8; CHALLENGE_SIZE];
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
    #[allow(trivially_copy_pass_by_ref)]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}
