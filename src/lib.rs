//! yubihsm-client: client for `YubiHSM2` hardware security modules

#![crate_name = "yubihsm_client"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate aesni;
#[macro_use]
extern crate bitflags;
extern crate block_modes;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
extern crate constant_time_eq;
#[cfg(feature = "mockhsm")]
extern crate ed25519_dalek;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate hmac;
extern crate pbkdf2;
extern crate rand;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha2;

/// Custom error macros for using enums with descriptions for errors
macro_rules! err {
    ($errtype:ident::$variant:ident, $msg:expr) => {
        $errtype::$variant { description: $msg.to_owned() }
    };
    ($errtype:ident::$variant:ident, $fmt:expr, $($arg:tt)+) => {
        $errtype::$variant { description: format!($fmt, $($arg)+) }
    };
}

macro_rules! fail {
    ($errtype:ident::$variant:ident, $msg:expr) => {
        return Err(err!($errtype::$variant, $msg).into());
    };
    ($errtype:ident::$variant:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(err!($errtype::$variant, $fmt, $($arg)+).into());
    };
}

pub mod algorithm;
pub mod capabilities;
mod commands;
pub mod connector;
pub mod domains;
#[cfg(any(feature = "mockhsm"))]
pub mod mockhsm;
pub mod object;
pub mod responses;
mod securechannel;
mod serializers;
pub mod session;

pub use algorithm::Algorithm;
pub use capabilities::Capabilities;
pub use connector::Connector;
pub use domains::{Domain, Domains};
pub use object::Id as ObjectId;
pub use object::Label as ObjectLabel;
pub use object::Origin as ObjectOrigin;
pub use object::Type as ObjectType;
pub use object::SequenceId;
pub use securechannel::SessionId;
pub use session::{Session, SessionError};
