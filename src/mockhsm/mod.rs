#[cfg(not(debug_assertions))]
compile_error!("MockHSM is not intended for use in release builds");

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

mod adapter;
mod commands;
mod objects;
mod session;
mod state;

pub use self::adapter::MockAdapter;
use self::state::State;
use auth_key::AuthKey;
use credentials::Credentials;
use object::ObjectId;
use session::{connection::Connection, Session, SessionTimeout};

/// Software simulation of a `YubiHSM2` intended for testing
/// implemented as a `yubihsm::Adapter`.
///
/// This only implements a subset of the YubiHSM's functionality, and does
/// not enforce access control. It's recommended to also test live against
/// a real device.
///
/// To enable, make sure to build yubihsm.rs with the `mockhsm` cargo feature
pub struct MockHSM(Arc<Mutex<State>>);

impl MockHSM {
    /// Create a new MockHSM
    pub fn new() -> Self {
        MockHSM(Arc::new(Mutex::new(State::new())))
    }

    /// Create a simulated session with a MockHSM
    pub fn create_session<K: Into<AuthKey>>(
        &self,
        auth_key_id: ObjectId,
        auth_key: K,
    ) -> Session<MockAdapter> {
        Session {
            connection: self.connection(),
            credentials: Some(Credentials::new(auth_key_id, auth_key.into())),
            last_command_timestamp: Instant::now(),
            timeout: SessionTimeout::default(),
        }
    }

    /// Create a `Connection` containing the `MockAdapter`
    // TODO: refactor `Connection` so we don't need to create it this way
    fn connection(&self) -> Connection<MockAdapter> {
        Connection {
            adapter: Some(MockAdapter::new(self.0.clone())),
            channel: None,
            config: MockConfig {},
        }
    }
}

impl Default for MockHSM {
    fn default() -> Self {
        Self::new()
    }
}

/// Fake config
#[derive(Debug, Default)]
pub struct MockConfig {}

impl fmt::Display for MockConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(nothing to see here)")
    }
}
