//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem support
//! (signing/encryption).
//!
//! NOTE: This functionality has not been properly tested and is therefore
//! not enabled by default! Enable the `untested` cargo feature if you would
//! like to use it (please report success or bugs!)

// TODO(tarcieri): finalize and test RSA support

mod algorithm;
pub mod mgf;

pub mod oaep;
pub mod pkcs1;
pub mod pss;

pub use self::algorithm::*;
