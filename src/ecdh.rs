//! Elliptic Curve Diffie Hellman Key Exchange.
//!
//! **WARNING**: This functionality has not been tested and has not yet been
//! confirmed to actually work! USE AT YOUR OWN RISK!
//!
//! You will need to enable the `untested` cargo feature to use it.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Derive_Ecdh.html>

mod algorithm;
#[cfg(feature = "untested")]
pub(crate) mod commands;
mod point;

pub use self::{algorithm::Algorithm, point::UncompressedPoint};
