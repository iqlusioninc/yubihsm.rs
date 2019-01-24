//! Sessions with the `MockHsm`

use std::fmt::{self, Debug};

use crate::command::CommandMessage;
use crate::response::ResponseMessage;
use crate::session::{
    securechannel::{Challenge, Cryptogram, SecureChannel},
    SessionId,
};

/// Session with the `MockHsm`
pub(crate) struct HsmSession {
    /// ID of the session
    pub id: SessionId,

    /// Card challenge for this session
    pub card_challenge: Challenge,

    /// Encrypted channel
    pub channel: SecureChannel,
}

impl HsmSession {
    /// Create a new session
    pub fn new(id: SessionId, card_challenge: Challenge, channel: SecureChannel) -> Self {
        Self {
            id,
            card_challenge,
            channel,
        }
    }

    /// Get the card challenge for this session
    pub fn card_challenge(&self) -> &Challenge {
        &self.card_challenge
    }

    /// Get the card cryptogram for this session
    pub fn card_cryptogram(&self) -> Cryptogram {
        self.channel.card_cryptogram()
    }

    /// Decrypt an incoming command
    pub fn decrypt_command(&mut self, command: CommandMessage) -> CommandMessage {
        self.channel.decrypt_command(command).unwrap()
    }

    /// Encrypt an outgoing response
    pub fn encrypt_response(&mut self, response: ResponseMessage) -> ResponseMessage {
        self.channel.encrypt_response(response).unwrap()
    }
}

impl Debug for HsmSession {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mockhsm::Session {{ id: {} }}", self.id.to_u8())
    }
}
