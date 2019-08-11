//! Digital signature (i.e. Ed25519) provider for `YubiHSM 2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM 2`, then
//! call the appropriate signer methods to obtain signers.

use crate::{object, Client};
use signatory::{ed25519, public_key::PublicKeyed};
use signature::Error;

/// Ed25519 signature provider for yubihsm-client
pub struct Signer {
    /// Session with the YubiHSM
    client: Client,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: object::Id,
}

impl Signer {
    /// Create a new YubiHSM-backed Ed25519 signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let signer = Self {
            client,
            signing_key_id,
        };

        // Ensure the signing_key_id slot contains a valid Ed25519 public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl PublicKeyed<ed25519::PublicKey> for Signer {
    fn public_key(&self) -> Result<ed25519::PublicKey, Error> {
        let public_key = self.client.get_public_key(self.signing_key_id)?;
        public_key.ed25519().ok_or_else(Error::new)
    }
}

impl signature::Signer<ed25519::Signature> for Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, Error> {
        Ok(self.client.sign_ed25519(self.signing_key_id, msg)?)
    }
}
