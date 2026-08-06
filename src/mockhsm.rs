//! Simulation of the HSM for integration testing.
//!
//! # Warning
//!
//! **This is a simulation, not an HSM. It is neither safe nor fit for
//! production use.**
//!
//! `MockHsm` accepts any credentials, holds all key material in process
//! memory, and performs none of the isolation a real YubiHSM 2 provides.
//! Anything it "protects" is readable by the process using it.
//!
//! It exists so downstream crates can run integration tests without hardware.
//! Enabling the `mockhsm` feature in a binary that talks to a real device is a
//! mistake; enabling it in production is a vulnerability.
//!
//! # Optimized builds
//!
//! Building `mockhsm` without debug assertions additionally requires the
//! `mockhsm-in-release` feature:
//!
//! ```text
//! cargo test --release --features=mockhsm,mockhsm-in-release
//! ```
//!
//! Running a test suite under `--release` is a legitimate reason to do this, so
//! it is allowed — but it has to be asked for. Cargo features are additive and
//! unify across a dependency graph, so `mockhsm` alone can be switched on by
//! something else in the tree; requiring a second, explicitly-named feature
//! means a simulated HSM cannot end up in an optimized binary by accident.

// Optimized builds must opt in explicitly; see the module docs above.
#[cfg(all(not(debug_assertions), not(feature = "mockhsm-in-release")))]
compile_error!(
    "the `mockhsm` feature is a simulation with no security properties and is \
     being built without debug assertions. If this is a test run, also enable \
     the `mockhsm-in-release` feature to acknowledge that. If it is not, \
     disable the `mockhsm` feature."
);

use std::sync::{Arc, Mutex};

mod audit;
mod command;
mod connection;
mod error;
mod object;
mod session;
mod state;

use self::state::State;
pub use self::{
    connection::MockConnection,
    error::{Error, ErrorKind},
};
use crate::connector::{self, Connectable, Connection};

/// Mock serial number for the MockHsm
pub const MOCK_SERIAL_NUMBER: &str = "0123456789";

/// Software simulation of a `YubiHSM 2` intended for testing
/// implemented as a `yubihsm::Connection`.
///
/// This only implements a subset of the YubiHSM's functionality, and does
/// *NOT* properly enforce access control / capabilities!
///
/// It is *STRONGLY* recommended to also test live against a real device.
///
/// To enable, make sure to build yubihsm.rs with the `mockhsm` cargo feature
#[derive(Clone, Debug)]
pub struct MockHsm(Arc<Mutex<State>>);

impl MockHsm {
    /// Create a new MockHsm
    ///
    /// # Warning
    ///
    /// This is a simulation and provides no security whatsoever. See the
    /// [module documentation][self] before using it for anything but tests.
    pub fn new() -> Self {
        // The `mockhsm` feature may legitimately be enabled in optimized
        // builds (running a downstream test suite under `--release`, distro
        // packaging), so this cannot be a hard error. Make it loud instead:
        // anyone who reaches this in a production binary sees it in the log.
        #[cfg(not(debug_assertions))]
        log::warn!(
            "SECURITY: yubihsm::MockHsm instantiated in an optimized build. \
             This is a simulation with no security properties -- it accepts any \
             credentials and keeps key material in process memory. If this is \
             not a test run, disable the `mockhsm` cargo feature."
        );

        MockHsm(Arc::new(Mutex::new(State::new())))
    }
}

impl Connectable for MockHsm {
    /// Make a clone of this connectable as boxed trait object
    fn box_clone(&self) -> Box<dyn Connectable> {
        Box::new(MockHsm(self.0.clone()))
    }

    /// Create a new connection with a clone of the MockHsm state
    fn connect(&self) -> Result<Box<dyn Connection>, connector::Error> {
        Ok(Box::new(MockConnection::new(self)))
    }
}

impl Default for MockHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl Into<Box<dyn Connectable>> for MockHsm {
    fn into(self) -> Box<dyn Connectable> {
        Box::new(self)
    }
}
