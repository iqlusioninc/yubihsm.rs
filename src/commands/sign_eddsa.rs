//! Compute an Ed25519 signature with the given key ID
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Eddsa.html>

use std::fmt::{self, Debug};

use super::{Command, Response};
use {CommandType, Connector, ObjectId, Session, SessionError};

/// Size of an Ed25519 signature
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Compute an Ed25519 signature with the given key ID
pub fn sign_ed25519<C, T>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: T,
) -> Result<Ed25519Signature, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session.send_encrypted_command(SignDataEdDSACommand {
        key_id,
        data: data.into(),
    })
}

/// Request parameters for `commands::sign_ed25519`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataEdDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Data to be signed
    pub data: Vec<u8>,
}

impl Command for SignDataEdDSACommand {
    type ResponseType = Ed25519Signature;
}

/// Ed25519 signature (64-bytes) response from `commands::sign_ed25519`
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl Response for Ed25519Signature {
    const COMMAND_TYPE: CommandType = CommandType::SignDataEdDSA;
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519Signature(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(
                f,
                "{}",
                if i == ED25519_SIGNATURE_SIZE - 1 {
                    ")"
                } else {
                    ":"
                }
            )?;
        }
        Ok(())
    }
}

impl_array_serializers!(Ed25519Signature, ED25519_SIGNATURE_SIZE);
