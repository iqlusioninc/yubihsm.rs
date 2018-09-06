#[cfg(not(debug_assertions))]
compile_error!("MockHSM is not intended for use in release builds");

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};
use uuid::Uuid;

mod commands;
mod objects;
mod session;
mod state;

use self::state::State;
use adapters::{Adapter, AdapterError, AdapterErrorKind};
use auth_key::AuthKey;
use commands::CommandType;
use credentials::Credentials;
use object::ObjectId;
use securechannel::CommandMessage;
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
            adapter: Some(MockAdapter(self.0.clone())),
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

/// A mocked connection to the MockHSM
pub struct MockAdapter(Arc<Mutex<State>>);

/// Fake config
#[derive(Debug, Default)]
pub struct MockConfig {}

impl fmt::Display for MockConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(nothing to see here)")
    }
}

impl Adapter for MockAdapter {
    type Config = MockConfig;

    /// We don't bother to implement this
    // TODO: use this as the entry point for the `MockHSM`'s `Arc<Mutex<State>>`?
    fn open(_config: &MockConfig) -> Result<Self, AdapterError> {
        panic!("unimplemented");
    }

    /// Rust never sleeps
    fn is_open(&self) -> bool {
        true
    }

    /// Send a message to the MockHSM
    fn send_message(&self, _uuid: Uuid, body: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let command = CommandMessage::parse(body).map_err(|e| {
            AdapterError::new(
                AdapterErrorKind::ConnectionFailed,
                Some(format!("error parsing command: {}", e)),
            )
        })?;

        let mut state = self.0.lock().map_err(|e| {
            AdapterError::new(
                AdapterErrorKind::ConnectionFailed,
                Some(format!("error obtaining state lock: {}", e)),
            )
        })?;

        match command.command_type {
            CommandType::CreateSession => commands::create_session(&mut state, &command),
            CommandType::AuthSession => commands::authenticate_session(&mut state, &command),
            CommandType::SessionMessage => commands::session_message(&mut state, command),
            unsupported => Err(AdapterError::new(
                AdapterErrorKind::ConnectionFailed,
                Some(format!("unsupported command: {:?}", unsupported)),
            )),
        }
    }
}
