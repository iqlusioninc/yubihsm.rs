//! yubihsm.rs: client for `YubiHSM2` hardware security modules
//!
//! # Build Notes
//!
//! This crate depends on the `aesni` crate, which uses the "stdsimd"
//! API to invoke hardware AES instructions via `core::arch`.
//!
//! To access these features, you will need both a relatively recent
//! Rust nightly and to pass the following as RUSTFLAGS:
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
//! let mut session = Session::create_from_password(
//!     "http://127.0.0.1:12345",
//!     1,
//!     "password",
//!     true
//! ).unwrap();
//!
//! // Note: You'll need to create this key first. Run the following from yubihsm-shell:
//! // `generate asymmetric 0 100 ed25519_test_key 1 asymmetric_sign_eddsa ed25519`
//! let response = session.sign_data_eddsa(100, "Hello, world!").unwrap();
//! println!("Ed25519 signature: {:?}", response.signature);
//! ```

#![crate_name = "yubihsm"]
#![crate_type = "rlib"]
#![cfg_attr(feature = "bench", feature(test))]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/yubihsm/0.5.0")]

extern crate aesni;
#[macro_use]
extern crate bitflags;
extern crate block_modes;
extern crate byteorder;
extern crate clear_on_drop;
extern crate cmac;
extern crate constant_time_eq;
#[cfg(feature = "dalek")]
extern crate ed25519_dalek;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate hmac;
extern crate pbkdf2;
extern crate rand;
#[cfg(feature = "reqwest-connector")]
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha2;
#[cfg(feature = "bench")]
extern crate test;

#[macro_use]
mod macros;

pub mod algorithm;
#[cfg(feature = "bench")]
mod bench;
pub mod capabilities;
mod commands;
pub mod connector;
pub mod domains;
#[cfg(feature = "mockhsm")]
pub mod mockhsm;
pub mod object;
pub mod responses;
mod securechannel;
mod serializers;
pub mod session;

pub use algorithm::Algorithm;
pub use capabilities::Capabilities;
pub use connector::Connector;
#[cfg(feature = "reqwest-connector")]
pub use connector::ReqwestConnector;
pub use domains::Domains;
pub use object::Id as ObjectId;
pub use object::Label as ObjectLabel;
pub use object::Origin as ObjectOrigin;
pub use object::Type as ObjectType;
pub use object::SequenceId;
pub use securechannel::SessionId;
pub use session::{AbstractSession, Session, SessionError};
