//! Cryptographic sessions within the SCP03 protocol

use challenge::CHALLENGE_SIZE;
use context::Context;
use clear_on_drop::clear::Clear;
use cryptogram::{self, Cryptogram};
use identity::IdentityKeys;
use super::KEY_SIZE;

/// Session keys as derived from per-session challenges
#[allow(dead_code)]
pub struct SessionKeys {
    // Session encryption key (S-ENC)
    enc_key: [u8; KEY_SIZE],

    // Session Command MAC key (S-MAC)
    mac_key: [u8; KEY_SIZE],

    // Session Respose MAC key (S-RMAC)
    rmac_key: [u8; KEY_SIZE],
}

impl SessionKeys {
    /// Derive session keys from static identity keys and host/card challenges
    pub fn derive(static_keys: &IdentityKeys, context: &Context) -> Self {
        let enc_key = derive_key(&static_keys.enc_key, 0b100, &context);
        let mac_key = derive_key(&static_keys.mac_key, 0b110, &context);
        let rmac_key = derive_key(&static_keys.mac_key, 0b111, &context);

        Self {
            enc_key,
            mac_key,
            rmac_key,
        }
    }

    /// Obtain the card cryptogram for this session
    pub fn card_cryptogram(&self, context: &Context) -> Cryptogram {
        let mut result_slice = [0u8; CHALLENGE_SIZE];
        cryptogram::calculate(&self.mac_key, 0, context, &mut result_slice);

        let result = Cryptogram::from_slice(&result_slice);
        result_slice.clear();

        result
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.enc_key.clear();
        self.mac_key.clear();
        self.rmac_key.clear();
    }
}

/// Derive a key using the SCP03 cryptogram protocol
fn derive_key(
    parent_key: &[u8; KEY_SIZE],
    derivation_constant: u8,
    context: &Context,
) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    cryptogram::calculate(parent_key, derivation_constant, context, &mut key);
    key
}
