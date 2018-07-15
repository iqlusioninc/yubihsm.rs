//! Compute HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Hmac_Data.html>

use super::{Command, Response};
use {CommandType, Connector, ObjectId, Session, SessionError};

/// Compute an HMAC tag of the given data with the given key ID
pub fn hmac<C, D>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: D,
) -> Result<HMACTag, SessionError>
where
    C: Connector,
    D: Into<Vec<u8>>,
{
    session.send_encrypted_command(HMACDataCommand {
        key_id,
        data: data.into(),
    })
}

/// Request parameters for `commands::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct HMACDataCommand {
    /// ID of the HMAC key
    pub key_id: ObjectId,

    /// Data to be authenticated
    pub data: Vec<u8>,
}

impl Command for HMACDataCommand {
    type ResponseType = HMACTag;
}

/// HMAC tags
#[derive(Serialize, Deserialize, Debug)]
pub struct HMACTag(pub Vec<u8>);

impl Response for HMACTag {
    const COMMAND_TYPE: CommandType = CommandType::HMACData;
}

#[allow(unknown_lints, len_without_is_empty)]
impl HMACTag {
    /// Create a new HMAC tag
    pub fn new<V: Into<Vec<u8>>>(vec: V) -> HMACTag {
        HMACTag(vec.into())
    }

    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the tag
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

impl AsRef<[u8]> for HMACTag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for HMACTag {
    fn from(vec: Vec<u8>) -> HMACTag {
        HMACTag::new(vec)
    }
}

impl<'a> From<&'a [u8]> for HMACTag {
    fn from(slice: &'a [u8]) -> HMACTag {
        HMACTag::from(slice.to_vec())
    }
}

impl Into<Vec<u8>> for HMACTag {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
