//! NIST P-521 elliptic curve.
//!
//! ## About
//!
//! NIST P-521 is a Weierstrass curve specified in FIPS 186-4: Digital Signature
//! Standard (DSS):
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>

pub use p521::NistP521;

/// ECDSA/P-521 signature (fixed-size)
pub type Signature = super::Signature<NistP521>;

/// ECDSA/P-521 signer
pub type Signer = super::Signer<NistP521>;
