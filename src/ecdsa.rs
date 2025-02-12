//! Elliptic Curve Digital Signature Algorithm (ECDSA) support

pub mod algorithm;
pub mod nistp256;
pub mod nistp384;
pub mod nistp521;

#[cfg(feature = "secp256k1")]
pub mod secp256k1;

pub(crate) mod commands;
mod signer;

pub use self::{
    algorithm::Algorithm, nistp256::NistP256, nistp384::NistP384, nistp521::NistP521,
    signer::Signer,
};
pub use ::ecdsa::{der, elliptic_curve::sec1, signature, Signature};

#[cfg(feature = "secp256k1")]
pub use self::secp256k1::Secp256k1;
