//! NIST P-384 elliptic curve.
//!
//! ## About
//!
//! NIST P-384 is a Weierstrass curve specified in FIPS 186-4: Digital Signature
//! Standard (DSS):
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>

pub use p384::NistP384;

/// ECDSA/P-384 signature (fixed-size)
pub type Signature = super::Signature<NistP384>;

/// ECDSA/P-384 signer
pub type Signer = super::Signer<NistP384>;
