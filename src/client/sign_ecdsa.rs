//! Compute an ECDSA signature with the given key ID.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Ecdsa.html>

use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::sign_ecdsa*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataECDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignDataECDSACommand {
    type ResponseType = ECDSASignature;
}

/// ECDSA signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct ECDSASignature(pub Vec<u8>);

impl Response for ECDSASignature {
    const COMMAND_CODE: CommandCode = CommandCode::SignDataECDSA;
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(
    unknown_lints,
    renamed_and_removed_lints,
    len_without_is_empty
)]
impl ECDSASignature {
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

impl AsRef<[u8]> for ECDSASignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for ECDSASignature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
