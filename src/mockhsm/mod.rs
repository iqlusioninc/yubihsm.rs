use std::fmt;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod commands;
mod objects;
mod session;
mod state;

use self::state::State;
use super::{ObjectId, StaticKeys};
use commands::CommandType;
use connector::{Connector, ConnectorError, ConnectorErrorKind, Status};
use securechannel::CommandMessage;
use session::{PBKDF2_ITERATIONS, PBKDF2_SALT, Session, SessionError};

/// Software simulation of a `YubiHSM2` intended for testing
/// implemented as a `yubihsm::Connector` (skipping HTTP transport)
///
/// To enable, make sure to build yubihsm.rs with the "mockhsm" feature
pub struct MockHSM {
    state: Arc<Mutex<State>>,
}

impl MockHSM {
    /// Create a new MockHSM
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::new())),
        }
    }

    /// Create a simulated session with a MockHSM
    pub fn create_session(
        auth_key_id: ObjectId,
        password: &str,
    ) -> Result<Session<Self>, SessionError> {
        let mockhsm = Self::default();
        let static_keys =
            StaticKeys::derive_from_password(password.as_bytes(), PBKDF2_SALT, PBKDF2_ITERATIONS);

        Session::new(mockhsm, auth_key_id, static_keys, false)
    }
}

impl Default for MockHSM {
    fn default() -> Self {
        Self::new()
    }
}

/// Fake config
#[derive(Debug, Default)]
pub struct MockConfig;

impl fmt::Display for MockConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(nothing to see here)")
    }
}

impl Connector for MockHSM {
    type Config = MockConfig;

    /// We don't bother to implement this
    fn open(_config: MockConfig) -> Result<Self, ConnectorError> {
        panic!("use MockHSM::create_session() to open a MockHSM session");
    }

    /// GET /connector/status returning the result as connector::Status
    fn status(&self) -> Result<Status, ConnectorError> {
        Ok(Status {
            message: "OK".to_owned(),
            serial: None,
            version: "1.0.1".to_owned(),
            pid: 12_345,
        })
    }

    /// POST /connector/api with a given command message and return the response message
    fn send_command(&self, _uuid: Uuid, body: Vec<u8>) -> Result<Vec<u8>, ConnectorError> {
        let command = CommandMessage::parse(body).map_err(|e| {
            ConnectorError::new(
                ConnectorErrorKind::ConnectionFailed,
                Some(format!("error parsing command: {}", e)),
            )
        })?;

        let mut state = self.state.lock().map_err(|e| {
            ConnectorError::new(
                ConnectorErrorKind::ConnectionFailed,
                Some(format!("error obtaining state lock: {}", e)),
            )
        })?;

        match command.command_type {
            CommandType::CreateSession => commands::create_session(&mut state, &command),
            CommandType::AuthSession => commands::authenticate_session(&mut state, &command),
            CommandType::SessionMessage => commands::session_message(&mut state, command),
            unsupported => Err(ConnectorError::new(
                ConnectorErrorKind::ConnectionFailed,
                Some(format!("unsupported command: {:?}", unsupported)),
            )),
        }
    }
}
