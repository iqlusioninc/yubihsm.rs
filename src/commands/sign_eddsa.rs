//! Compute an Ed25519 signature with the given key ID
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Eddsa.html>

use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
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

impl Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Ed25519Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Ed25519SignatureVisitor;

        impl<'de> Visitor<'de> for Ed25519SignatureVisitor {
            type Value = Ed25519Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Ed25519 signature (64-bytes)")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Ed25519Signature, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut label = [0; ED25519_SIGNATURE_SIZE];

                for elem in label.iter_mut().take(ED25519_SIGNATURE_SIZE) {
                    match seq.next_element()? {
                        Some(val) => *elem = val,
                        None => return Err(de::Error::custom("end of stream")),
                    };
                }

                Ok(Ed25519Signature(label))
            }
        }

        deserializer.deserialize_seq(Ed25519SignatureVisitor)
    }
}
