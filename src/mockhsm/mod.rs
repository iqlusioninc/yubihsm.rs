#[cfg(not(debug_assertions))]
compile_error!("MockHsm is not intended for use in release builds");

use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use std::sync::{Arc, Mutex};

mod adapter;
mod audit;
mod command;
mod object;
mod session;
mod state;

pub use self::adapter::MockAdapter;
use self::state::State;
use client::Client;

/// Software simulation of a `YubiHSM2` intended for testing
/// implemented as a `yubihsm::Adapter`.
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

impl Default for MockHsm {
    fn default() -> Self {
        Self::new()
    }
}

// This is required by the `Adapter` trait
impl Serialize for MockHsm {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        panic!("unimplemented");
    }
}

// This is required by the `Adapter` trait
impl<'de> Deserialize<'de> for MockHsm {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<MockHsm, D::Error> {
        panic!("unimplemented");
    }
}

/// Drop-in replacement `Session` type which uses `MockHsm`
pub type MockSession = Client<MockAdapter>;
