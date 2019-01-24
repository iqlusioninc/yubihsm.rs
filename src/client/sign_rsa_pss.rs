//! Compute an RSASSA-PSS signature of the SHA-256 hash of the given data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Pss.html>

use crate::{
    algorithm::Algorithm,
    command::{Command, CommandCode},
    object::ObjectId,
    response::Response,
};

/// Maximum message size supported for RSASSA-PSS
pub const RSA_PSS_MAX_MESSAGE_SIZE: usize = 0xFFFF;

/// Request parameters for `command::sign_rsa_pss*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataPSSCommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Hash algorithm to use for MGF1
    pub mgf1_hash_alg: Algorithm,

    /// Salt length
    pub salt_len: u16,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignDataPSSCommand {
    type ResponseType = RSAPSSSignature;
}

/// RSASSA-PSS signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct RSAPSSSignature(pub Vec<u8>);

impl Response for RSAPSSSignature {
    const COMMAND_CODE: CommandCode = CommandCode::SignDataPSS;
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(unknown_lints, renamed_and_removed_lints, len_without_is_empty)]
impl RSAPSSSignature {
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

impl AsRef<[u8]> for RSAPSSSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for RSAPSSSignature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
