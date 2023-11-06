//! RSA-PSS signatures

use serde::{Deserialize, Serialize};
use signature::SignatureEncoding;

/// RSASSA-PSS signatures (ASN.1 DER encoded)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Signature(pub Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl Signature {
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

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for Signature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl From<&::rsa::pss::Signature> for Signature {
    fn from(s: &::rsa::pss::Signature) -> Self {
        Self(<::rsa::pss::Signature as SignatureEncoding>::to_vec(s))
    }
}
