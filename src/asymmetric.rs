//! Asymmetric cryptography i.e. digital signatures and public-key encryption.
//!
//! This module contains types and functionality common to all asymmetric
//! algorithms.
//!
//! Functionality specific to a particular algorithm is available in toplevel
//! modules (e.g. `attestation`, `ecdsa`, `ed25519`)

mod algorithm;
pub(crate) mod commands;
mod public_key;

pub use self::{algorithm::Algorithm, public_key::PublicKey};
pub use signature;
