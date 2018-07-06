//! Have the card echo an input message
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>

use super::{Command, Response};
use {CommandType, Connector, Session, SessionError};

/// Have the card echo an input message
pub fn echo<C, T>(session: &mut Session<C>, message: T) -> Result<EchoResponse, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session.send_encrypted_command(EchoCommand {
        message: message.into(),
    })
}

/// Request parameters for `commands::echo`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    type ResponseType = EchoResponse;
}

/// Response from `commands::ccho`
#[derive(Serialize, Deserialize, Debug)]
pub struct EchoResponse(pub Vec<u8>);

impl Response for EchoResponse {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
}

impl EchoResponse {
    /// Unwrap inner byte vector
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the echo data
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is the echo response empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get slice of the inner byte vector
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for EchoResponse {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "mockhsm")]
impl<'a> From<&'a [u8]> for EchoResponse {
    fn from(slice: &'a [u8]) -> Self {
        EchoResponse(slice.into())
    }
}

impl Into<Vec<u8>> for EchoResponse {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
