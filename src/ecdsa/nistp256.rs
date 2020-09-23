//! NIST P-256 elliptic curve (a.k.a. prime256v1, secp256r1)
//!
//! ## About
//!
//! NIST P-256 is a Weierstrass curve specified in FIPS 186-4: Digital Signature
//! Standard (DSS):
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! Also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG), it's included in
//! the US National Security Agency's "Suite B" and is widely used in protocols
//! like TLS and the associated X.509 PKI.

pub use p256::NistP256;

/// ECDSA/P-256 signature (fixed-size)
pub type Signature = super::Signature<NistP256>;

/// ECDSA/P-256 signer
pub type Signer = super::Signer<NistP256>;
