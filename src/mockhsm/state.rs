//! `MockHSM` presents a thread-safe API by locking interior mutable state,
//! contained in the `State` struct defined in this module.

use std::collections::BTreeMap;

use connector::{ConnectorError, ConnectorErrorKind};
use object::{ObjectId, ObjectType};
use securechannel::{Challenge, Channel, SessionId};

use super::objects::Objects;
use super::session::Session;

/// Mutable interior state of the `MockHSM`
pub(crate) struct State {
    sessions: BTreeMap<SessionId, Session>,
    pub objects: Objects,
}

impl State {
    /// Create a new instance of the server's mutable interior state
    pub fn new() -> Self {
        Self {
            sessions: BTreeMap::new(),
            objects: Objects::default(),
        }
    }

    /// Create a new session with the MockHSM
    pub fn create_session(&mut self, auth_key_id: ObjectId, host_challenge: Challenge) -> &Session {
        // Generate a random card challenge to send back to the client
        let card_challenge = Challenge::random();

        let session_id = self
            .sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| SessionId::new(0).unwrap());

        let channel = {
            let auth_key_obj = self
                .objects
                .get(auth_key_id, ObjectType::AuthKey)
                .unwrap_or_else(|| panic!("MockHSM has no AuthKey in slot {:?}", auth_key_id));

            Channel::new(
                session_id,
                auth_key_obj.payload.auth_key().expect("auth key payload"),
                host_challenge,
                card_challenge,
            )
        };

        let session = Session::new(session_id, card_challenge, channel);
        assert!(self.sessions.insert(session_id, session).is_none());

        self.get_session(session_id).unwrap()
    }

    /// Obtain the channel for a session by its ID
    pub fn get_session(&mut self, id: SessionId) -> Result<&mut Session, ConnectorError> {
        self.sessions.get_mut(&id).ok_or_else(|| {
            ConnectorError::new(
                ConnectorErrorKind::RequestError,
                Some(format!("invalid session ID: {:?}", id)),
            )
        })
    }

    /// Close an active session
    pub fn close_session(&mut self, id: SessionId) {
        assert!(self.sessions.remove(&id).is_some());
    }

    /// Reset the internal HSM state, closing all connections
    pub fn reset(&mut self) {
        self.sessions = BTreeMap::new();
        self.objects = Objects::default();
    }
}
