//! Digital signature (i.e. Ed25519) provider for `YubiHSM 2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM 2`, then
//! call the appropriate signer methods to obtain signers.

use crate::{asymmetric, object, Client};
use signatory::{
    ed25519,
    error::{Error, ErrorKind::*},
    PublicKeyed, Signature,
};

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
        let pubkey = self.client.get_public_key(self.signing_key_id)?;

        if pubkey.algorithm == asymmetric::Algorithm::Ed25519 {
            Ok(ed25519::PublicKey::from_bytes(pubkey.as_ref()).unwrap())
        } else {
            Err(Error::new(
                KeyInvalid,
                Some(&format!(
                    "expected an ed25519 key, got: {:?}",
                    pubkey.algorithm
                )),
            ))
        }
    }
}

impl signatory::Signer<ed25519::Signature> for Signer {
    fn sign(&self, msg: &[u8]) -> Result<ed25519::Signature, Error> {
        let signature = self.client.sign_ed25519(self.signing_key_id, msg)?;
        Ok(ed25519::Signature::from_bytes(signature.as_ref()).unwrap())
    }
}
