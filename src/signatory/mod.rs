/// Signatory adapter: multi-provider digital signature library for Rust
///
/// <https://github.com/tendermint/signatory>

#[macro_use]
mod error;
pub mod ecdsa;
pub mod ed25519;
mod session;

pub use self::{ecdsa::EcdsaSigner, ed25519::Ed25519Signer, session::Session};
pub use signatory::Signer;
