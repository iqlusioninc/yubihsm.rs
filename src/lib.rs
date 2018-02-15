//! yubihsm-client: client for YubiHSM2 hardware security modules

#![crate_name = "yubihsm_client"]
#![crate_type = "bin"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate byteorder;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate reqwest;
extern crate scp03;

pub(crate) mod command;
pub mod connector;
#[cfg(any(feature = "mockhsm"))]
pub mod mockhsm;
pub mod session;

pub use connector::Connector;

/// Key identifiers
pub type KeyID = u16;
