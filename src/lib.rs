//! **yubihsm.rs**: pure Rust client for YubiHSM 2 hardware security modules
//!
//! ## Prerequisites
//!
//! This crate builds on Rust 1.40+ and by default uses SIMD features
//! which require the following `RUSTFLAGS`:
//!
//! `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3`
//!
//! You can configure your `~/.cargo/config` to always pass these flags:
//!
//! ```toml
//! [build]
//! rustflags = ["-Ctarget-feature=+aes,+ssse3"]
//! ```
//!
//! # Getting Started
//!
//! Most crate functionality can be found in the `Client` type:
//!
//! * [yubihsm::Client: main API for all YubiHSM functionality! Start here!][yubihsm::Client]
//!
//! In order to connect to the HSM, you'll need to make a [yubihsm::Connector].
//!
//! # Example
//!
//! The following is an example of how to create a [yubihsm::Client] by
//! connecting via USB, and then performing an Ed25519 signature:
//!
//! ```no_build
//! use yubihsm::{Client, Credentials, UsbConnector};
//!
//! // Connect to the first YubiHSM 2 we detect
//! let connector = UsbConnector::default();
//!
//! // Default auth key ID and password for YubiHSM 2
//! // NOTE: DON'T USE THIS IN PRODUCTION!
//! let credentials = Credentials::default();
//!
//! // Connect to the HSM and authenticate with the given credentials
//! let mut hsm_client = Client::open(connector, credentials, true).unwrap();
//!
//! // Note: You'll need to create this key first. Run the following from yubihsm-shell:
//! // `generate asymmetric 0 100 ed25519_test_key 1 asymmetric_sign_eddsa ed25519`
//! let signature = hsm_client.sign_ed25519(100, "Hello, world!").unwrap();
//! println!("Ed25519 signature: {:?}", signature);
//! ```
//!
//! [yubihsm::Connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html
//! [yubihsm::Client]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html
//! [commands]: https://developers.yubico.com/YubiHSM2/Commands/
//! [yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/iqlusioninc/yubihsm.rs/develop/img/logo.png",
    html_root_url = "https://docs.rs/yubihsm/0.33.0"
)]

#[macro_use]
extern crate log;

#[macro_use]
mod macros;
#[macro_use]
pub mod error;
#[macro_use]
mod serialization;

pub mod algorithm;
pub mod asymmetric;
pub mod attestation;
pub mod audit;
pub mod authentication;
pub mod capability;
pub mod client;
pub mod command;
pub mod connector;
pub mod device;
pub mod domain;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod hmac;
#[cfg(feature = "mockhsm")]
pub(crate) mod mockhsm;
pub mod object;
pub mod opaque;
pub mod otp;
pub mod response;
pub mod rsa;
pub mod session;
#[cfg(feature = "setup")]
pub mod setup;
pub mod ssh;
pub mod template;
mod uuid;
pub mod wrap;

#[cfg(feature = "http")]
pub use crate::connector::HttpConfig;
#[cfg(feature = "usb")]
pub use crate::connector::UsbConfig;

pub use crate::{
    algorithm::Algorithm, audit::AuditOption, authentication::Credentials, capability::Capability,
    client::Client, connector::Connector, domain::Domain, error::*, uuid::Uuid,
};
