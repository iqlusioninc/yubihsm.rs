//! Compute an ECDSA signature with the given key ID.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Ecdsa.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Request parameters for `command::sign_ecdsa*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignEcdsaCommand {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignEcdsaCommand {
    type ResponseType = EcdsaSignature;
}

/// ECDSA signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct EcdsaSignature(pub Vec<u8>);

impl Response for EcdsaSignature {
    const COMMAND_CODE: command::Code = command::Code::SignEcdsa;
}

#[allow(clippy::len_without_is_empty)]
impl EcdsaSignature {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the signature
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for EcdsaSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for EcdsaSignature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
