use super::{SessionError, SessionErrorKind::ProtocolError};

/// Maximum session identifier
pub const MAX_SESSION_ID: SessionId = SessionId(16);

/// Session/Channel IDs
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct SessionId(u8);

impl SessionId {
    /// Create a new session ID from a byte value
    pub fn new(id: u8) -> Result<Self, SessionError> {
        if id > MAX_SESSION_ID.0 {
            fail!(
                ProtocolError,
                "session ID exceeds the maximum allowed: {} (max {})",
                id,
                MAX_SESSION_ID.0
            );
        }

        Ok(SessionId(id))
    }

    /// Obtain the next session ID
    pub fn succ(self) -> Result<Self, SessionError> {
        Self::new(self.0 + 1)
    }

    /// Obtain session ID as a u8
    pub fn to_u8(self) -> u8 {
        self.0
    }
}
