//! Attestation Certificates: generate an X.509 certificate which attests that
//! a key generated with a YubiHSM is genuine

mod certificate;
pub(crate) mod commands;

pub use self::certificate::Certificate;
