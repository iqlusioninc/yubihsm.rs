//! `MockHsm` presents a thread-safe API by locking interior mutable state,
//! contained in the `State` struct defined in this module.

use std::collections::BTreeMap;

use adapter::{AdapterError, AdapterErrorKind};
use audit::AuditOption;
use object::{ObjectId, ObjectType};
use session::{
    securechannel::{Challenge, SecureChannel},
    SessionId,
};

use super::{audit::CommandAuditOptions, object::Objects, session::HsmSession};

/// Mutable interior state of the `MockHsm`
#[derive(Debug)]
pub(crate) struct State {
    /// Command-specific audit options
    pub(super) command_audit_options: CommandAuditOptions,

    /// Don't allow command to be performed until log data has been consumed
    /// via the `SetLogIndex` command.
    pub(super) force_audit: AuditOption,

    /// Active sessions with the MockHsm
    sessions: BTreeMap<SessionId, HsmSession>,

    /// Objects within the MockHsm (i.e. keys)
    pub(super) objects: Objects,
}

impl State {
    /// Create a new instance of the server's mutable interior state
    pub fn new() -> Self {
        Self {
            command_audit_options: CommandAuditOptions::default(),
            force_audit: AuditOption::Off,
            sessions: BTreeMap::new(),
            objects: Objects::default(),
        }
    }

    /// Create a new session with the MockHsm
    pub fn create_session(
        &mut self,
        auth_key_id: ObjectId,
        host_challenge: Challenge,
    ) -> &HsmSession {
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
                .unwrap_or_else(|| panic!("MockHsm has no AuthKey in slot {:?}", auth_key_id));

            SecureChannel::new(
                session_id,
                auth_key_obj.payload.auth_key().expect("auth key payload"),
                host_challenge,
                card_challenge,
            )
        };

        let session = HsmSession::new(session_id, card_challenge, channel);
        assert!(self.sessions.insert(session_id, session).is_none());

        self.get_session(session_id).unwrap()
    }

    /// Obtain the channel for a session by its ID
    pub fn get_session(&mut self, id: SessionId) -> Result<&mut HsmSession, AdapterError> {
        self.sessions.get_mut(&id).ok_or_else(|| {
            AdapterError::new(
                AdapterErrorKind::RequestError,
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
        self.command_audit_options = CommandAuditOptions::default();
        self.sessions = BTreeMap::new();
        self.objects = Objects::default();
    }
}
