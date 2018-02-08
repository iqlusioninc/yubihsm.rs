//! yubihsm-client: client for YubiHSM2 hardware security modules

#![crate_name = "yubihsm_client"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate reqwest;

/// Client for yubihsm-connector and main entry point to library
pub mod connector;

pub use connector::Connector;
