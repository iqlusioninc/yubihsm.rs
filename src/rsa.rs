//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem support
//! (signing/encryption).
//!
//! NOTE: This functionality has not been properly tested and is therefore
//! not enabled by default! Enable the `yolocrypto` cargo feature if you would
//! like to use it (please report success or bugs!)

// TODO(tarcieri): finalize and test RSA support

mod algorithm;
pub mod mgf;

#[cfg(feature = "yolocrypto")]
pub mod pkcs1;
#[cfg(feature = "yolocrypto")]
pub mod pss;

pub use self::algorithm::*;
