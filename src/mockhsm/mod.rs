//! Software simulation of the `YubiHSM2` for integration testing,
//! implemented as a `yubihsm::Connector` (skipping HTTP transport)
//!
//! To enable, make sure to build yubihsm.rs with the "mockhsm" feature

use failure::Error;
use std::sync::{Arc, Mutex};

mod objects;
mod state;

use connector::{Connector, Status};
use securechannel::{CommandMessage, CommandType};
use session::{PBKDF2_ITERATIONS, PBKDF2_SALT, Session};
use super::{ObjectId, StaticKeys};
use self::state::State;

/// Software simulation of a `YubiHSM2` intended for testing
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
    pub fn create_session(auth_key_id: ObjectId, password: &str) -> Result<Session<Self>, Error> {
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

impl Connector for MockHSM {
    /// We don't bother to implement this
    fn open(_url: &str) -> Result<Self, Error> {
        panic!("use MockHSM::create_session() to open a MockHSM session");
    }

    /// GET /connector/status returning the result as connector::Status
    fn status(&self) -> Result<Status, Error> {
        Ok(Status {
            message: "OK".to_owned(),
            serial: None,
            version: "1.0.1".to_owned(),
            pid: 12_345,
        })
    }

    /// POST /connector/api with a given command message and return the response message
    fn send_command(&self, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let command = CommandMessage::parse(body).unwrap();
        let mut state = self.state.lock().unwrap();

        match command.command_type {
            CommandType::CreateSession => state.create_session(&command),
            CommandType::AuthSession => state.authenticate_session(&command),
            CommandType::SessionMessage => state.session_message(command),
            unsupported => panic!("unsupported command type: {:?}", unsupported),
        }
    }
}
