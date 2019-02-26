//! Ed25519 signatures

use std::fmt::{self, Debug};

/// Size of an Ed25519 signature
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signature (64-bytes)
#[derive(Clone)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519::Signature(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(f, "{}", if i == SIGNATURE_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}

impl_array_serializers!(Signature, SIGNATURE_SIZE);
