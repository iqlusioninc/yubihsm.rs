//! Compute an Ed25519 signature with the given key ID
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use std::fmt::{self, Debug};

/// Size of an Ed25519 signature
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Request parameters for `command::sign_ed25519`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataEddsaCommand {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Data to be signed
    pub data: Vec<u8>,
}

impl Command for SignDataEddsaCommand {
    type ResponseType = Ed25519Signature;
}

/// Ed25519 signature (64-bytes) response from `command::sign_ed25519`
pub struct Ed25519Signature(pub [u8; ED25519_SIGNATURE_SIZE]);

impl Response for Ed25519Signature {
    const COMMAND_CODE: command::Code = command::Code::SignEddsa;
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
