//! RSASSA-PKCS#1v1.5 commands
//!
//! Note: This is a legacy algorithm. Greenfield projects should consider
//! non-RSA algorithms like Ed25519 or ECDSA, or RSA-PSS if RSA is required.

mod algorithm;
pub(crate) mod commands;
mod signature;
mod signer;

pub use self::algorithm::Algorithm;
pub use self::signature::Signature;
pub use self::signer::Signer;
