//! Implementation of the GlobalPlatform Secure Channel Protocol "03" used by YubiHSM2
//!
//! See GPC_SPE_014: GlobalPlatform Card Technology Secure Channel Protocol '03' at:
//! <https://www.globalplatform.org/specificationscard.asp>

#![crate_name = "scp03"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate aesni;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
extern crate constant_time_eq;
extern crate hmac;
extern crate pbkdf2;
extern crate rand;
extern crate sha2;

mod challenge;
mod context;
mod cryptogram;
mod identity;
mod session;

/// AES key size in bytes
pub const KEY_SIZE: usize = 16;

pub use challenge::Challenge;
pub use context::Context;
pub use cryptogram::Cryptogram;
pub use identity::IdentityKeys;
pub use session::SessionKeys;
