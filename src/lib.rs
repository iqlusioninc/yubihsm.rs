//! yubihsm-client: client for `YubiHSM2` hardware security modules

#![crate_name = "yubihsm_client"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate aesni;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
extern crate constant_time_eq;
#[cfg_attr(feature = "mockhsm", macro_use)]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate hmac;
extern crate pbkdf2;
extern crate rand;
extern crate reqwest;
extern crate sha2;

pub mod connector;
#[cfg(any(feature = "mockhsm"))]
pub mod mockhsm;
mod securechannel;
pub mod session;

pub use connector::Connector;
pub use securechannel::SessionId;

/// Key identifiers
pub type KeyId = u16;
