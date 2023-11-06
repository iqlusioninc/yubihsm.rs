//! RSA-related algorithms

use super::{mgf, oaep, pkcs1, pss};
use crate::algorithm;
use digest::{const_oid::AssociatedOid, Digest};

/// RSA algorithms (signing and encryption)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// RSA encryption with Optimal Asymmetric Encryption Padding (OAEP)
    Oaep(oaep::Algorithm),

    /// RSA PKCS#1v1.5: legacy signature and encryption algorithms
    Pkcs1(pkcs1::Algorithm),

    /// RSASSA-PSS: Probabilistic Signature Scheme
    Pss(pss::Algorithm),
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x01..=0x04 => Algorithm::Pkcs1(pkcs1::Algorithm::from_u8(tag)?),
            0x05..=0x08 => Algorithm::Pss(pss::Algorithm::from_u8(tag)?),
            0x19..=0x1c => Algorithm::Oaep(oaep::Algorithm::from_u8(tag)?),
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown RSA algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        match self {
            Algorithm::Oaep(alg) => alg.to_u8(),
            Algorithm::Pkcs1(alg) => alg.to_u8(),
            Algorithm::Pss(alg) => alg.to_u8(),
        }
    }
}

impl_algorithm_serializers!(Algorithm);

impl From<oaep::Algorithm> for Algorithm {
    fn from(alg: oaep::Algorithm) -> Algorithm {
        Algorithm::Oaep(alg)
    }
}

impl From<pkcs1::Algorithm> for Algorithm {
    fn from(alg: pkcs1::Algorithm) -> Algorithm {
        Algorithm::Pkcs1(alg)
    }
}

impl From<pss::Algorithm> for Algorithm {
    fn from(alg: pss::Algorithm) -> Algorithm {
        Algorithm::Pss(alg)
    }
}

/// [`SignatureAlgorithm`] marks the digest algorithm support for RSA signature (PSS or PKCS#1v1.5).
pub trait SignatureAlgorithm: Digest + AssociatedOid {
    /// Mask Generation Function to use when talking to the YubiHSM.
    const MGF_ALGORITHM: mgf::Algorithm;
}

impl SignatureAlgorithm for sha1::Sha1 {
    const MGF_ALGORITHM: mgf::Algorithm = mgf::Algorithm::Sha1;
}

impl SignatureAlgorithm for sha2::Sha256 {
    const MGF_ALGORITHM: mgf::Algorithm = mgf::Algorithm::Sha256;
}

impl SignatureAlgorithm for sha2::Sha384 {
    const MGF_ALGORITHM: mgf::Algorithm = mgf::Algorithm::Sha384;
}

impl SignatureAlgorithm for sha2::Sha512 {
    const MGF_ALGORITHM: mgf::Algorithm = mgf::Algorithm::Sha512;
}
