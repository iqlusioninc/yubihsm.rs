//! Public keys for use with asymmetric cryptography / signatures

use crate::{asymmetric, ecdsa::algorithm::CurveAlgorithm, ed25519};
use ::ecdsa::elliptic_curve::{
    generic_array::{typenum::Unsigned, GenericArray},
    point::PointCompression,
    sec1, FieldBytesSize, PrimeCurve,
};
use num_traits::FromPrimitive;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};

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
    pub fn ecdsa<C>(&self) -> Option<sec1::EncodedPoint<C>>
    where
        C: PrimeCurve + CurveAlgorithm + PointCompression,
        FieldBytesSize<C>: sec1::ModulusSize,
    {
        if self.algorithm != C::asymmetric_algorithm()
            || self.bytes.len() != FieldBytesSize::<C>::USIZE * 2
        {
            return None;
        }

        let mut bytes = GenericArray::default();
        bytes.copy_from_slice(&self.bytes);
        let result = sec1::EncodedPoint::<C>::from_untagged_bytes(&bytes);

        if C::COMPRESS_POINTS {
            Some(result.compress())
        } else {
            Some(result)
        }
    }

    /// Return the Ed25519 public key if applicable
    pub fn ed25519(&self) -> Option<ed25519::PublicKey> {
        if self.algorithm == asymmetric::Algorithm::Ed25519 {
            ed25519::PublicKey::from_bytes(&self.bytes)
        } else {
            None
        }
    }

    /// Return the RSA public key
    pub fn rsa(&self) -> Option<RsaPublicKey> {
        if !self.algorithm.is_rsa() {
            return None;
        }

        const EXP: u64 = 65537;

        let modulus = BigUint::from_bytes_be(&self.bytes);
        let exp = BigUint::from_u64(EXP).expect("invalid static exponent");

        RsaPublicKey::new(modulus, exp).ok()
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
