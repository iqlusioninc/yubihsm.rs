//! HMAC tags

use serde::{Deserialize, Serialize};

/// HMAC tags
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tag(pub Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl Tag {
    /// Create a new HMAC tag
    pub fn new<V: Into<Vec<u8>>>(vec: V) -> Tag {
        Tag(vec.into())
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

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for Tag {
    fn from(vec: Vec<u8>) -> Tag {
        Tag::new(vec)
    }
}

impl<'a> From<&'a [u8]> for Tag {
    fn from(slice: &'a [u8]) -> Tag {
        Tag::from(slice.to_vec())
    }
}

impl Into<Vec<u8>> for Tag {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
