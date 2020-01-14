//! `MockHsm` presents a thread-safe API by locking interior mutable state,
//! contained in the `State` struct defined in this module.

use super::{audit::CommandAuditOptions, object::Objects, session::HsmSession};
use crate::{
    audit::AuditOption,
    connector, object,
    session::{
        self,
        securechannel::{Challenge, SecureChannel},
    },
};
use anomaly::format_err;
use std::collections::BTreeMap;

/// Mutable interior state of the `MockHsm`
#[derive(Debug)]
pub(crate) struct State {
    /// Command-specific audit options
    pub(super) command_audit_options: CommandAuditOptions,

    /// Don't allow command to be performed until log data has been consumed
    /// via the `SetLogIndex` command.
    pub(super) force_audit: AuditOption,

    /// Active sessions with the MockHsm
    sessions: BTreeMap<session::Id, HsmSession>,

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
        authentication_key_id: object::Id,
        host_challenge: Challenge,
    ) -> &HsmSession {
        // Generate a random card challenge to send back to the client
        let card_challenge = Challenge::new();

        let session_id = self
            .sessions
            .keys()
            .max()
            .map(|id| id.succ().expect("session count exceeded"))
            .unwrap_or_else(|| session::Id::from_u8(0).unwrap());

        let channel = {
            let authentication_key_obj = self
                .objects
                .get(authentication_key_id, object::Type::AuthenticationKey)
                .unwrap_or_else(|| {
                    panic!(
                        "MockHsm has no authentication::Key in slot {:?}",
                        authentication_key_id
                    )
                });

            SecureChannel::new(
                session_id,
                authentication_key_obj
                    .payload
                    .authentication_key()
                    .expect("auth key payload"),
                host_challenge,
                card_challenge,
            )
        };

        let session = HsmSession::new(session_id, card_challenge, channel);
        assert!(self.sessions.insert(session_id, session).is_none());

        self.get_session(session_id).unwrap()
    }

    /// Obtain the channel for a session by its ID
    pub fn get_session(&mut self, id: session::Id) -> Result<&mut HsmSession, connector::Error> {
        self.sessions.get_mut(&id).ok_or_else(|| {
            format_err!(
                connector::ErrorKind::RequestError,
                "invalid session ID: {:?}",
                id
            )
            .into()
        })
    }

    /// Close an active session
    pub fn close_session(&mut self, id: session::Id) {
        assert!(self.sessions.remove(&id).is_some());
    }

    /// Reset the internal HSM state, closing all connections
    pub fn reset(&mut self) {
        self.command_audit_options = CommandAuditOptions::default();
        self.sessions = BTreeMap::new();
        self.objects = Objects::default();
    }
}
