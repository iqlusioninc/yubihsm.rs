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
use self::state::State;

/// Software simulation of a `YubiHSM2` intended for testing
pub struct MockHSM {
    state: Arc<Mutex<State>>,
}

impl Connector for MockHSM {
    /// Open a connection to a yubihsm-connector
    fn open(_url: &str) -> Result<Self, Error> {
        Ok(Self {
            state: Arc::new(Mutex::new(State::new())),
        })
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
