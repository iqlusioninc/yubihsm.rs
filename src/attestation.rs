//! Attestation Certificates: generate an X.509 certificate which attests that
//! a key generated with a YubiHSM is genuine

use crate::object;

mod certificate;
pub(crate) mod commands;
mod pkix;

pub use self::certificate::Certificate;
pub use self::pkix::*;

/// Default attestation key ID slot
pub const DEFAULT_ATTESTATION_KEY_ID: object::Id = 0;
