#[cfg(not(debug_assertions))]
compile_error!("MockHsm is not intended for use in release builds");

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

mod audit;
mod command;
mod connection;
mod object;
mod session;
mod state;

pub use self::connection::MockConnection;
use self::state::State;
use connector::{Connection, ConnectionError, Connector};
use serial_number::SerialNumber;

/// Mock serial number for the MockHsm
pub const MOCK_SERIAL_NUMBER: &str = "0123456789";

/// Software simulation of a `YubiHSM2` intended for testing
/// implemented as a `yubihsm::Connection`.
///
/// This only implements a subset of the YubiHSM's functionality, and does
/// not enforce access control. It's recommended to also test live against
/// a real device.
///
/// To enable, make sure to build yubihsm.rs with the `mockhsm` cargo feature
#[derive(Debug)]
pub struct MockHsm(Arc<Mutex<State>>);

impl MockHsm {
    /// Create a new MockHsm
    pub fn new() -> Self {
        MockHsm(Arc::new(Mutex::new(State::new())))
    }
}

impl Connector for MockHsm {
    /// Create a new connection with a clone of the MockHsm state
    fn connect(&self) -> Result<Box<Connection>, ConnectionError> {
        Ok(Box::new(MockConnection::new(self)))
    }

    /// Rust never sleeps
    fn healthcheck(&self) -> Result<(), ConnectionError> {
        Ok(())
    }

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, ConnectionError> {
        Ok(SerialNumber::from_str(MOCK_SERIAL_NUMBER).unwrap())
    }
}

impl Default for MockHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl Into<Box<Connector>> for MockHsm {
    fn into(self) -> Box<Connector> {
        Box::new(self)
    }
}
