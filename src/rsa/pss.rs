//! RSASSA-PSS: Probabilistic Signature Scheme based on the RSASP1 and RSAVP1
//! primitives with the EMSA-PSS encoding method.

mod algorithm;
#[cfg(feature = "yolocrypto")]
pub(crate) mod commands;
#[cfg(feature = "yolocrypto")]
mod signature;

/// Maximum message size supported for RSASSA-PSS
#[cfg(feature = "yolocrypto")]
pub const MAX_MESSAGE_SIZE: usize = 0xFFFF;

pub use self::algorithm::Algorithm;
#[cfg(feature = "yolocrypto")]
pub use self::signature::Signature;
