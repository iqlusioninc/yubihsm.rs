//! Elliptic Curve Digital Signature Algorithm (ECDSA) support

pub mod algorithm;
pub mod nistp256;
pub mod nistp384;

#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub mod secp256k1;

pub(crate) mod commands;
mod signer;

pub use self::{algorithm::Algorithm, nistp256::NistP256, nistp384::NistP384, signer::Signer};
pub use ::ecdsa::{asn1, elliptic_curve::sec1, signature, Signature};

#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub use self::secp256k1::Secp256k1;
