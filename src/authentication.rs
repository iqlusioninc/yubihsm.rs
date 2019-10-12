//! YubiHSM 2 authentication functionality (i.e. credentials used to
//! authenticate and establish a session with an HSM)

mod algorithm;
pub mod commands;
mod credentials;
mod error;
pub mod key;

pub use self::{
    algorithm::Algorithm,
    credentials::*,
    error::{Error, ErrorKind},
    key::Key,
};
