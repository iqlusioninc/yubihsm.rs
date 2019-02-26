//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem support (signing/encryption)

mod algorithm;
pub mod mgf;

// TODO(tarcieri): finalize and test RSA support
// Until then, it's gated behind the `rsa` feature
#[cfg(feature = "rsa")]
pub mod pkcs1;
#[cfg(feature = "rsa")]
pub mod pss;

pub use self::algorithm::*;
