//! Derivation context (i.e. concatenated challenges)

use super::{derive_key, Challenge, SessionKeys, CHALLENGE_SIZE};
use crate::authentication;

/// Size of a session context
const CONTEXT_SIZE: usize = CHALLENGE_SIZE * 2;

/// Derivation context (i.e. concatenated challenges)
pub struct Context([u8; CONTEXT_SIZE]);

impl Context {
    /// Create a derivation context from host and card challenges
    pub fn from_challenges(host_challenge: Challenge, card_challenge: Challenge) -> Self {
        let mut context = [0u8; CONTEXT_SIZE];
        context[..CHALLENGE_SIZE].copy_from_slice(host_challenge.as_slice());
        context[CHALLENGE_SIZE..].copy_from_slice(card_challenge.as_slice());
        Context(context)
    }

    /// Borrow the context value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Derive session keys from context and authentication key
    pub fn derive_keys(&self, authentication_key: &authentication::Key) -> SessionKeys {
        let enc_key = derive_key(authentication_key.enc_key(), 0b100, self);
        let mac_key = derive_key(authentication_key.mac_key(), 0b110, self);
        let rmac_key = derive_key(authentication_key.mac_key(), 0b111, self);

        SessionKeys {
            enc_key,
            mac_key,
            rmac_key,
        }
    }
}

#[cfg(feature = "yubihsm-auth")]
impl From<Context> for yubikey::hsmauth::Context {
    fn from(context: Context) -> Self {
        Self::from_buf(context.0)
    }
}
