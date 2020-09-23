//! Ed25519 digital signature algorithm support

pub(crate) mod commands;
mod public_key;
mod signer;

pub use self::{public_key::PublicKey, signer::Signer};
pub use ::ed25519::{Signature, SIGNATURE_LENGTH as SIGNATURE_SIZE};
