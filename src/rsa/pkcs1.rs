//! RSASSA-PKCS#1v1.5 commands
//!
//! Note: This is a legacy algorithm. Greenfield projects should consider
//! non-RSA algorithms like Ed25519 or ECDSA, or RSA-PSS if RSA is required.

pub(crate) mod commands;
mod signature;

pub use self::signature::Signature;
