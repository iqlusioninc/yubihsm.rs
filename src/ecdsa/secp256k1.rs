//! secp256k1 elliptic curve
//!
//! ## About
//!
//! The secp256k1 elliptic curve is specified by Certicom's SECG in
//! "SEC 2: Recommended Elliptic Curve Domain Parameters":
//!
//! <https://www.secg.org/sec2-v2.pdf>
//!
//! It's primarily notable for usage in Bitcoin and other cryptocurrencies.

pub use k256::Secp256k1;

/// ECDSA/secp256k1 signature (fixed-size)
pub type Signature = super::Signature<Secp256k1>;

/// ECDSA/secp256k1 signer
pub type Signer = super::Signer<Secp256k1>;
