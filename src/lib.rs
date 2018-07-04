//! yubihsm.rs: client for `YubiHSM2` hardware security modules
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
//! The main type you'll want to check out is `Session`. Here is an example of
//! how to connect to [yubihsm-connector] and perform an Ed25519 signature:
//!
//! [yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
//!
//! ```no_run
//! use yubihsm::Session;
//!
//! // Default host, port, auth key ID, and password for yubihsm-connector
//! let mut session =
//!     Session::create_from_password(Default::default(), 1, "password", true).unwrap();
//!
//! // Note: You'll need to create this key first. Run the following from yubihsm-shell:
//! // `generate asymmetric 0 100 ed25519_test_key 1 asymmetric_sign_eddsa ed25519`
//! let response = session.sign_ed25519(100, "Hello, world!").unwrap();
//! println!("Ed25519 signature: {:?}", response.signature);
//! ```

#![crate_name = "yubihsm"]
#![crate_type = "rlib"]
#![cfg_attr(feature = "bench", feature(test))]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/yubihsm/0.10.1")]

extern crate aes;
#[macro_use]
extern crate bitflags;
extern crate block_modes;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
extern crate constant_time_eq;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[cfg(feature = "hmac")]
extern crate hmac;
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
#[cfg(feature = "bench")]
extern crate test;
#[cfg(feature = "mockhsm")]
extern crate untrusted;
extern crate uuid;

/// Error types
pub mod error;

/// Cryptographic algorithms supported by the `YubiHSM2`
pub mod algorithm;

/// Object attributes specifying which operations are allowed to be performed
pub mod capability;

/// Command (i.e. request) structs for `YubiHSM` commands
mod commands;

/// Client for the `yubihsm-connector` service
pub mod connector;

/// Logical partitions within the `YubiHSM`, allowing several applications to share the device
pub mod domain;
#[cfg(feature = "mockhsm")]

/// Software simulation of the `YubiHSM2` for integration testing,
pub mod mockhsm;

/// Objects stored in the `YubiHSM2`
///
/// For more information, see:
/// <https://developers.yubico.com/YubiHSM2/Concepts/Object.html>
pub mod object;

/// Responses to commands sent from the HSM
pub mod responses;

/// Encrypted communication channel to the YubiHSM hardware
mod securechannel;

/// Serde-powered serializers for the `YubiHSM` wire format
mod serializers;

/// `YubiHSM2` sessions: primary API for performing HSM operations
///
/// See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
pub mod session;

pub use algorithm::Algorithm;
pub use capability::Capability;
pub use connector::{Connector, HttpConfig, HttpConnector};
pub use domain::Domain;
pub use object::Id as ObjectId;
pub use object::Label as ObjectLabel;
pub use object::Origin as ObjectOrigin;
pub use object::SequenceId;
pub use object::Type as ObjectType;
pub use securechannel::{SessionId, StaticKeys};
pub use session::{Session, SessionError};
