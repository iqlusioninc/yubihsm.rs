use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

use super::{command, state::State, MockHsm};
use adapter::{Adapter, AdapterError, AdapterErrorKind::ConnectionFailed};
use command::CommandType;
use serial_number::SerialNumber;
use session::CommandMessage;

/// A mocked connection to the MockHsm
pub struct MockAdapter(Arc<Mutex<State>>);

/// Mock serial number for the MockHsm
pub const MOCK_SERIAL_NUMBER: &str = "0123456789";

impl Adapter for MockAdapter {
    type Config = MockHsm;

    /// Create a new adapter with a clone of the MockHsm state
    fn open(hsm: &MockHsm) -> Result<Self, AdapterError> {
        Ok(MockAdapter(hsm.0.clone()))
    }

    /// Rust never sleeps
    fn healthcheck(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, AdapterError> {
        Ok(SerialNumber::from_str(MOCK_SERIAL_NUMBER).unwrap())
    }

    /// Send a message to the MockHsm
    fn send_message(&self, _uuid: Uuid, body: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let command = CommandMessage::parse(body)
            .map_err(|e| err!(ConnectionFailed, "error parsing command: {}", e))?;

        let mut state = self
            .0
            .lock()
            .map_err(|e| err!(ConnectionFailed, "error obtaining state lock: {}", e))?;

        match command.command_type {
            CommandType::CreateSession => command::create_session(&mut state, &command),
            CommandType::AuthSession => command::authenticate_session(&mut state, &command),
            CommandType::SessionMessage => command::session_message(&mut state, command),
            unsupported => fail!(ConnectionFailed, "unsupported command: {:?}", unsupported),
        }
    }
}
