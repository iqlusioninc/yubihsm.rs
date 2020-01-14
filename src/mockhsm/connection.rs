//! Mock connection to the MockHSM

use anomaly::{fail, format_err};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use super::{command, state::State, MockHsm};
use crate::{
    command::Code,
    connector::{self, Connection, ErrorKind::ConnectionFailed, Message},
};

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
    fn send_message(&self, _uuid: Uuid, message: Message) -> Result<Message, connector::Error> {
        let command = message
            .parse()
            .map_err(|e| format_err!(ConnectionFailed, "error parsing command: {}", e))?;

        let mut state = self
            .0
            .lock()
            .map_err(|e| format_err!(ConnectionFailed, "error obtaining state lock: {}", e))?;

        match command.command_type {
            Code::CreateSession => command::create_session(&mut state, &command),
            Code::AuthenticateSession => command::authenticate_session(&mut state, &command),
            Code::SessionMessage => command::session_message(&mut state, command),
            unsupported => fail!(ConnectionFailed, "unsupported command: {:?}", unsupported),
        }
        .map(Message::from)
    }
}
