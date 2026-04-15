//! AES key size algorithms for RSA-AES key wrapping (CKM_RSA_AES_KEY_WRAP)
//!
//! These represent the ephemeral AES key sizes used during RSA-AES wrap
//! operations (`get_rsa_wrapped_key`), not a general-purpose AES API.

mod algorithm;

pub use self::algorithm::Algorithm;
