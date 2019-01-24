use std::sync::{Arc, Mutex};
use uuid::Uuid;

use super::{command, state::State, MockHsm};
use crate::command::{CommandCode, CommandMessage};
use crate::connector::{Connection, ConnectionError, ConnectionErrorKind::ConnectionFailed};

/// A mocked connection to the MockHsm
pub struct MockConnection(Arc<Mutex<State>>);

impl MockConnection {
    /// Create a new connection with a clone of the MockHsm state
    pub(super) fn new(hsm: &MockHsm) -> Self {
        MockConnection(hsm.0.clone())
    }
}

impl Connection for MockConnection {
    /// Send a message to the MockHsm
    fn send_message(&self, _uuid: Uuid, body: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        let command = CommandMessage::parse(body)
            .map_err(|e| err!(ConnectionFailed, "error parsing command: {}", e))?;

        let mut state = self
            .0
            .lock()
            .map_err(|e| err!(ConnectionFailed, "error obtaining state lock: {}", e))?;

        match command.command_type {
            CommandCode::CreateSession => command::create_session(&mut state, &command),
            CommandCode::AuthSession => command::authenticate_session(&mut state, &command),
            CommandCode::SessionMessage => command::session_message(&mut state, command),
            unsupported => fail!(ConnectionFailed, "unsupported command: {:?}", unsupported),
        }
    }
}
