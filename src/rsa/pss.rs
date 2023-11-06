//! RSASSA-PSS: Probabilistic Signature Scheme based on the RSASP1 and RSAVP1
//! primitives with the EMSA-PSS encoding method.

mod algorithm;
pub(crate) mod commands;
mod signature;
mod signer;

/// Maximum message size supported for RSASSA-PSS
pub const MAX_MESSAGE_SIZE: usize = 0xFFFF;

pub use self::algorithm::Algorithm;
pub use self::signature::Signature;
pub use self::signer::Signer;
