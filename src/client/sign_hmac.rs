//! Compute HMAC tag for the given input data
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Hmac.html>

use crate::{
    command::{Command, CommandCode},
    object::ObjectId,
    response::Response,
};

/// Request parameters for `command::hmac`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignHmacCommand {
    /// ID of the HMAC key
    pub key_id: ObjectId,

    /// Data to be authenticated
    pub data: Vec<u8>,
}

impl Command for SignHmacCommand {
    type ResponseType = HmacTag;
}

/// HMAC tags
#[derive(Serialize, Deserialize, Debug)]
pub struct HmacTag(pub Vec<u8>);

impl Response for HmacTag {
    const COMMAND_CODE: CommandCode = CommandCode::SignHmac;
}

#[allow(clippy::len_without_is_empty)]
impl HmacTag {
    /// Create a new HMAC tag
    pub fn new<V: Into<Vec<u8>>>(vec: V) -> HmacTag {
        HmacTag(vec.into())
    }

    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the tag
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for HmacTag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for HmacTag {
    fn from(vec: Vec<u8>) -> HmacTag {
        HmacTag::new(vec)
    }
}

impl<'a> From<&'a [u8]> for HmacTag {
    fn from(slice: &'a [u8]) -> HmacTag {
        HmacTag::from(slice.to_vec())
    }
}

impl Into<Vec<u8>> for HmacTag {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
