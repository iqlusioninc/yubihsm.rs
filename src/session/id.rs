use super::{Error, ErrorKind::ProtocolError};

/// Maximum session identifier
pub const MAX_SESSION_ID: Id = Id(16);

/// Session/Channel IDs
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Id(u8);

impl Id {
    /// Create a new session ID from a byte value
    pub fn from_u8(id: u8) -> Result<Self, Error> {
        if id > MAX_SESSION_ID.0 {
            fail!(
                ProtocolError,
                "session ID exceeds the maximum allowed: {} (max {})",
                id,
                MAX_SESSION_ID.0
            );
        }

        Ok(Id(id))
    }

    /// Obtain the next session ID
    pub fn succ(self) -> Result<Self, Error> {
        Self::from_u8(self.0 + 1)
    }

    /// Obtain session ID as a u8
    pub fn to_u8(self) -> u8 {
        self.0
    }
}
