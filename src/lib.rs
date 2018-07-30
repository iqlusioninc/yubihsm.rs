//! yubihsm.rs: pure Rust client for `YubiHSM2` hardware security modules
//!
//! ## Prerequisites
//!
//! This crate builds on Rust 1.27+ and by default uses SIMD features
//! which require the following `RUSTFLAGS`:
//!
//! `RUSTFLAGS=-Ctarget-feature=+aes`
//!
//! You can configure your `~/.cargo/config` to always pass these flags:
//!
//! ```toml
//! [build]
//! rustflags = ["-Ctarget-feature=+aes"]
//! ```
//!
//! # Getting Started
//!
//! The following documentation describes the most important parts of this crate's API:
//!
//! * [Session]: end-to-end encrypted connection with the YubiHSM. You'll need an active one to do anything.
//! * [commands]: commands supported by the YubiHSM2 (i.e. main functionality)
//!
//! [Session]: https://docs.rs/yubihsm/latest/yubihsm/session/struct.Session.html
//! [commands]: https://docs.rs/yubihsm/latest/yubihsm/commands/index.html
//!
//! The following is an example of how to create a `Session` by connecting to a
//! [yubihsm-connector] process, and then performing an Ed25519 signature:
//!
//! [yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
//!
//! ```no_run
//! extern crate yubihsm;
//! use yubihsm::Session;
//!
//! // Default yubihsm-connector URI, auth key ID, and password for yubihsm-connector
//! let mut session =
//!     Session::create_from_password(Default::default(), 1, b"password", true).unwrap();
//!
//! // Note: You'll need to create this key first. Run the following from yubihsm-shell:
//! // `generate asymmetric 0 100 ed25519_test_key 1 asymmetric_sign_eddsa ed25519`
//! let signature = yubihsm::sign_ed25519(&mut session, 100, "Hello, world!").unwrap();
//! println!("Ed25519 signature: {:?}", signature);
//! ```

#![crate_name = "yubihsm"]
#![crate_type = "rlib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/yubihsm/0.14.2")]

extern crate aes;
#[macro_use]
extern crate bitflags;
extern crate block_modes;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[cfg(feature = "hmac")]
extern crate hmac;
#[macro_use]
extern crate log;
#[cfg(feature = "pbkdf2")]
extern crate pbkdf2;
extern crate rand;
#[cfg(feature = "ring")]
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "sha2")]
extern crate sha2;
extern crate subtle;
#[cfg(feature = "mockhsm")]
extern crate untrusted;
extern crate uuid;

/// Error types
pub mod error;

/// Serde-powered serializers for the `YubiHSM2` wire format
#[macro_use]
mod serializers;

/// Cryptographic algorithms supported by the `YubiHSM2`
pub mod algorithm;

/// Authentication keys used to establish encrypted sessions with the `YubiHSM2`
pub mod auth_key;

/// Object attributes specifying which operations are allowed to be performed
pub mod capabilities;

/// Commands supported by the `YubiHSM2`
///
/// Functions defined in the `yubihsm::commands` module are reimported
/// and available from the toplevel `yubihsm` module as well.
///
/// For more information, see:
/// <https://developers.yubico.com/YubiHSM2/Commands/>
pub mod commands;

/// Client for the `yubihsm-connector` service
pub mod connector;

/// Logical partitions within the `YubiHSM2`, allowing several applications to share the device
pub mod domains;

#[cfg(feature = "mockhsm")]
/// Software simulation of the `YubiHSM2` for integration testing
pub mod mockhsm;

/// Objects stored in the `YubiHSM2`
///
/// For more information, see:
/// <https://developers.yubico.com/YubiHSM2/Concepts/Object.html>
pub mod object;

/// Encrypted communication channel to the `YubiHSM2` hardware
mod securechannel;

/// `YubiHSM2` sessions: primary API for performing HSM operations
///
/// See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
pub mod session;

pub use algorithm::*;
pub use auth_key::*;
pub use capabilities::Capability;
// Import command functions from all submodules
pub use commands::{
    attest_asymmetric::*, blink::*, delete_object::*, device_info::*, echo::*, export_wrapped::*,
    generate_asymmetric_key::*, generate_hmac_key::*, generate_wrap_key::*, get_logs::*,
    get_object_info::*, get_opaque::*, get_pubkey::*, hmac::*, import_wrapped::*, list_objects::*,
    put_asymmetric_key::*, put_auth_key::*, put_hmac_key::*, put_opaque::*, put_otp_aead_key::*,
    put_wrap_key::*, reset::*, set_log_index::*, sign_ecdsa::*, sign_eddsa::*, storage_status::*,
    unwrap_data::*, verify_hmac::*, wrap_data::*, CommandType,
};
#[cfg(feature = "rsa")]
pub use commands::{sign_rsa_pkcs1v15::*, sign_rsa_pss::*};
pub use connector::{Connector, HttpConfig, HttpConnector};
pub use domains::Domain;
pub use object::*;
pub use securechannel::SessionId;
pub use session::{Session, SessionError};
