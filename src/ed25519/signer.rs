//! Digital signature (i.e. Ed25519) provider for `YubiHSM 2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM 2`, then
//! call the appropriate signer methods to obtain signers.

use crate::{ed25519::PublicKey, object, Client};
use signature::Error;

/// Ed25519 signature provider for yubihsm-client
pub struct Signer {
    /// Session with the YubiHSM
    client: Client,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: object::Id,

    /// Public key
    public_key: PublicKey,
}

impl Signer {
    /// Create a new YubiHSM-backed Ed25519 signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let public_key = client
            .get_public_key(signing_key_id)?
            .ed25519()
            .ok_or_else(Error::new)?;

        Ok(Self {
            client,
            signing_key_id,
            public_key,
        })
    }

    /// Get the public key for the YubiHSM-backed Ed25519 private key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl From<&Signer> for PublicKey {
    fn from(signer: &Signer) -> PublicKey {
        signer.public_key
    }
}

impl signature::Signer<ed25519::Signature> for Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, Error> {
        Ok(self.client.sign_ed25519(self.signing_key_id, msg)?)
    }
}
