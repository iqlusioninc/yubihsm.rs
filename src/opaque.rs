//! Opaque object support: store arbitrary data in the HSM

mod algorithm;
pub(crate) mod commands;

pub use self::algorithm::Algorithm;
