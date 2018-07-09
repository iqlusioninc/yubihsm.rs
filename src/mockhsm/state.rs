//! `MockHSM` presents a thread-safe API by locking interior mutable state,
//! contained in the `State` struct defined in this module.

use std::collections::BTreeMap;

use securechannel::{Challenge, Channel, StaticKeys};
use session::{PBKDF2_ITERATIONS, PBKDF2_SALT};
use SessionId;

use super::objects::Objects;
use super::session::Session;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Mutable interior state of the `MockHSM`
pub(crate) struct State {
    static_keys: StaticKeys,
    sessions: BTreeMap<SessionId, Session>,
    pub objects: Objects,
}

impl State {
    /// Create a new instance of the server's mutable interior state
    pub fn new() -> Self {
        Self {
            static_keys: StaticKeys::derive_from_password(
                DEFAULT_PASSWORD.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
            sessions: BTreeMap::new(),
            objects: Objects::default(),
        }
    }

    /// Create a new session with the MockHSM
    pub fn create_session(&mut self, host_challenge: Challenge) -> &Session {
        // Generate a random card challenge to send back to the client
        let card_challenge = Challenge::random();

        let session_id = self
            .sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| SessionId::new(0).unwrap());

        let channel = Channel::new(
            session_id,
            &self.static_keys,
            host_challenge,
            card_challenge,
        );

        let session = Session::new(session_id, card_challenge, channel);
        assert!(self.sessions.insert(session_id, session).is_none());

        self.get_session(session_id)
    }

    /// Obtain the channel for a session by its ID
    pub fn get_session(&mut self, id: SessionId) -> &mut Session {
        self.sessions
            .get_mut(&id)
            .unwrap_or_else(|| panic!("invalid session ID: {:?}", id))
    }

    /// Close an active session
    pub fn close_session(&mut self, id: SessionId) {
        assert!(self.sessions.remove(&id).is_some());
    }
}
