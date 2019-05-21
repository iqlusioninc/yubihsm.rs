//! Public keys for use with asymmetric cryptography / signatures

use crate::{asymmetric, ecdsa, ed25519};
use serde::{Deserialize, Serialize};
use signatory::{ecdsa::curve::WeierstrassCurveKind, generic_array::GenericArray};

/// Response from `command::get_public_key`
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey {
    /// Algorithm of the public key
    pub algorithm: asymmetric::Algorithm,

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

    /// Return the ECDSA public key of the given curve type if applicable
    pub fn ecdsa<C>(&self) -> Option<ecdsa::PublicKey<C>>
    where
        C: ecdsa::curve::WeierstrassCurve,
    {
        match self.algorithm {
            asymmetric::Algorithm::EC_P256 => {
                if C::CURVE_KIND == WeierstrassCurveKind::NistP256 {
                    Some(ecdsa::PublicKey::from_untagged_point(
                        GenericArray::from_slice(&self.bytes),
                    ))
                } else {
                    None
                }
            }
            asymmetric::Algorithm::EC_P384 => {
                if C::CURVE_KIND == WeierstrassCurveKind::NistP384 {
                    Some(ecdsa::PublicKey::from_untagged_point(
                        GenericArray::from_slice(&self.bytes),
                    ))
                } else {
                    None
                }
            }
            asymmetric::Algorithm::EC_K256 => {
                if C::CURVE_KIND == WeierstrassCurveKind::Secp256k1 {
                    Some(ecdsa::PublicKey::from_untagged_point(
                        GenericArray::from_slice(&self.bytes),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Return the Ed25519 public key if applicable
    pub fn ed25519(&self) -> Option<ed25519::PublicKey> {
        if self.algorithm == asymmetric::Algorithm::Ed25519 {
            ed25519::PublicKey::from_bytes(&self.bytes).ok()
        } else {
            None
        }
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
