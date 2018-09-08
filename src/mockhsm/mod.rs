#[cfg(not(debug_assertions))]
compile_error!("MockHSM is not intended for use in release builds");

use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use std::sync::{Arc, Mutex};

mod adapter;
mod commands;
mod objects;
mod session;
mod state;

pub use self::adapter::MockAdapter;
use self::state::State;

/// Software simulation of a `YubiHSM2` intended for testing
/// implemented as a `yubihsm::Adapter`.
///
/// This only implements a subset of the YubiHSM's functionality, and does
/// not enforce access control. It's recommended to also test live against
/// a real device.
///
/// To enable, make sure to build yubihsm.rs with the `mockhsm` cargo feature
#[derive(Debug)]
pub struct MockHSM(Arc<Mutex<State>>);

impl MockHSM {
    /// Create a new MockHSM
    pub fn new() -> Self {
        MockHSM(Arc::new(Mutex::new(State::new())))
    }
}

impl Default for MockHSM {
    fn default() -> Self {
        Self::new()
    }
}

// This is required by the `Adapter` trait
impl Serialize for MockHSM {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        panic!("unimplemented");
    }
}

// This is required by the `Adapter` trait
impl<'de> Deserialize<'de> for MockHSM {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<MockHSM, D::Error> {
        panic!("unimplemented");
    }
}
