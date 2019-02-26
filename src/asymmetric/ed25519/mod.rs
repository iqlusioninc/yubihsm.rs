//! Ed25519 digital signature algorithm support

pub(crate) mod commands;
mod signature;

pub use self::signature::{Signature, SIGNATURE_SIZE};
