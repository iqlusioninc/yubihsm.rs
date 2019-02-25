//! **yubihsm.rs**: pure Rust client for YubiHSM 2 hardware security modules
//!
//! ## Prerequisites
//!
//! This crate builds on Rust 1.31+ and by default uses SIMD features
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
//! The following documentation describes the most important parts of this crate's API:
//!
//! * [yubihsm::connector]: methods of connecting to a YubiHSM (USB or HTTP via [yubihsm-connector])
//! * [yubihsm::Client]: client providing wrappers for YubiHSM [commands].
//!
//! # Example
//!
//! The following is an example of how to create a [yubihsm::Client] by
//! connecting via USB, and then performing an Ed25519 signature:
//!
//! ```no_build
//! extern crate yubihsm;
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
//! [yubihsm::connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/index.html
//! [yubihsm::Client]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html
//! [commands]: https://developers.yubico.com/YubiHSM2/Commands/
//! [yubihsm-connector]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/

#![crate_name = "yubihsm"]
#![crate_type = "rlib"]
#![cfg_attr(clippy, feature(tool_lints))]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/yubihsm-rs/master/img/logo.png",
    html_root_url = "https://docs.rs/yubihsm/0.21.0-alpha1"
)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[cfg(feature = "usb")]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

#[macro_use]
mod macros;
#[macro_use]
pub mod error;
#[macro_use]
mod serialization;

pub mod algorithm;
pub mod audit;
pub mod authentication;
pub mod capability;
pub mod client;
pub mod command;
pub mod connector;
pub mod device;
pub mod domain;
#[cfg(feature = "mockhsm")]
pub mod mockhsm;
pub mod object;
pub mod response;
pub mod session;
#[cfg(feature = "setup")]
pub mod setup;
#[cfg(feature = "signatory")]
pub mod signatory;
pub mod wrap;

#[cfg(feature = "http")]
pub use crate::connector::HttpConfig;
#[cfg(feature = "usb")]
pub use crate::connector::UsbConfig;
#[cfg(feature = "mockhsm")]
pub use crate::mockhsm::MockHsm;

pub use crate::{
    algorithm::*,
    audit::AuditOption,
    authentication::{Credentials, AUTHENTICATION_KEY_SIZE},
    capability::Capability,
    client::{Client, ClientError},
    connector::{ConnectionError, Connector},
    device::{DeviceError, DeviceErrorKind},
    domain::Domain,
    error::*,
};
pub use uuid::Uuid;
