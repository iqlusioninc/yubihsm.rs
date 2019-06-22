//! Wrapper type around messages sent to/from the HSM

#[cfg(any(feature = "http-server", feature = "mockhsm"))]
use crate::{command, session};

/// Messages sent to/from the HSM
#[derive(Clone, Debug)]
pub struct Message(pub(crate) Vec<u8>);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for Message {
    fn from(vec: Vec<u8>) -> Message {
        Message(vec)
    }
}

impl From<Message> for Vec<u8> {
    fn from(vec: Message) -> Vec<u8> {
        vec.0
    }
}

impl Message {
    /// Parse a `command::Message` from this `connector::Message`
    #[cfg(any(feature = "http-server", feature = "mockhsm"))]
    pub(crate) fn parse(self) -> Result<command::Message, session::Error> {
        command::Message::parse(self.0)
    }
}
