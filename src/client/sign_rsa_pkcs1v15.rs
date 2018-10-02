//! Compute an RSASSA-PKCS#1v1.5 signature of the SHA-256 hash of the given data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Pkcs1.html>

use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::sign_rsa_pkcs1v15*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataPKCS1Command {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignDataPKCS1Command {
    type ResponseType = RSAPKCS1Signature;
}

/// RSASSA-PKCS#1v1.5 signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct RSAPKCS1Signature(pub Vec<u8>);

impl Response for RSAPKCS1Signature {
    const COMMAND_CODE: CommandCode = CommandCode::SignDataPKCS1;
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(
    unknown_lints,
    renamed_and_removed_lints,
    len_without_is_empty
)]
impl RSAPKCS1Signature {
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

impl AsRef<[u8]> for RSAPKCS1Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for RSAPKCS1Signature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
