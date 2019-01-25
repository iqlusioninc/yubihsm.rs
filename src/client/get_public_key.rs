//! Get the public key for an asymmetric key stored on the device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html>

use crate::{
    command::{Command, CommandCode},
    response::Response,
    AsymmetricAlg, ObjectId,
};

/// Request parameters for `command::get_public_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPubKeyCommand {
    /// Object ID of the key to obtain the corresponding pubkey for
    pub key_id: ObjectId,
}

impl Command for GetPubKeyCommand {
    type ResponseType = PublicKey;
}

/// Response from `command::get_public_key`
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    /// Algorithm of the public key
    pub algorithm: AsymmetricAlg,

    /// The public key in raw bytes. Keys have the following structure:
    ///
    /// - RSA: Public modulus N (0x100 | 0x200 | 0x400 bytes)
    /// - ECC (non-Ed25519):
    ///   - Public point X (0x20 | 0x30 | 0x40 | 0x42 bytes)
    ///   - Public point Y (0x20 | 0x30 | 0x40 | 0x42 bytes)
    /// - Ed25519: Public point A, compressed (0x20 bytes)
    ///
    /// In particular note that in the case of e.g. ECDSA public keys, many
    /// libraries will expect a 0x04 (DER OCTET STRING) tag byte at the
    /// beginning of the key. The YubiHSM does not return this, so you may
    /// need to add it depending on your particular application.
    pub bytes: Vec<u8>,
}

impl Response for PublicKey {
    const COMMAND_CODE: CommandCode = CommandCode::GetPublicKey;
}

#[allow(clippy::len_without_is_empty)]
impl PublicKey {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the key
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl Into<Vec<u8>> for PublicKey {
    fn into(self) -> Vec<u8> {
        self.bytes
    }
}
