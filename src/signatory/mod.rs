//! Signatory adapter: multi-provider digital signature library for Rust
//!
//! <https://github.com/tendermint/signatory>

#[macro_use]
mod error;
pub mod ecdsa;
pub mod ed25519;

pub use self::{ecdsa::EcdsaSigner, ed25519::Ed25519Signer};
pub use signatory::Signer;
