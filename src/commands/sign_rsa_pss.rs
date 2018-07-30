//! Compute an RSASSA-PSS signature of the SHA-256 hash of the given data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Pss.html>

use byteorder::{BigEndian, ByteOrder};

use super::{Command, Response};
use session::{Session, SessionError};
use sha2::{Digest, Sha256};
use Connector;
use {Algorithm, CommandType, ObjectId};

/// Maximum message size supported for RSASSA-PSS
pub const RSA_PSS_MAX_MESSAGE_SIZE: usize = 0xFFFF;

/// Compute an RSASSA-PSS signature of the SHA-256 hash of the given data with the given key ID.
///
/// WARNING: This method has not been tested and is not confirmed to actually work! Use at your
/// own risk!
pub fn sign_rsa_pss_sha256<C: Connector>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: &[u8],
) -> Result<RSAPSSSignature, SessionError> {
    if data.len() > RSA_PSS_MAX_MESSAGE_SIZE {
        command_fail!(
            ProtocolError,
            "message too large to be signed (max: {})",
            RSA_PSS_MAX_MESSAGE_SIZE
        );
    }

    let mut hasher = Sha256::default();

    let mut length = [0u8; 2];
    BigEndian::write_u16(&mut length, data.len() as u16);
    hasher.input(&length);
    hasher.input(data);
    let digest = hasher.result();

    session.send_encrypted_command(SignDataPSSCommand {
        key_id,
        mgf1_hash_alg: Algorithm::MGF1_SHA256,
        salt_len: digest.as_slice().len() as u16,
        digest: digest.as_slice().into(),
    })
}

/// Request parameters for `commands::sign_rsa_pss*`
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
    const COMMAND_TYPE: CommandType = CommandType::SignDataPSS;
}

#[allow(unknown_lints, len_without_is_empty)]
impl RSAPSSSignature {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the signature
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    #[inline]
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
