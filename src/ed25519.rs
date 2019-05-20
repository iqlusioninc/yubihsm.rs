//! Ed25519 digital signature algorithm support

pub(crate) mod commands;
mod signer;

pub use self::signer::Signer;
pub use signatory::ed25519::{PublicKey, Signature, SIGNATURE_SIZE};
