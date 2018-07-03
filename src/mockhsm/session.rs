//! Sessions with the `MockHSM`

use securechannel::{Challenge, Channel, CommandMessage, Cryptogram, ResponseMessage};
use SessionId;

/// Session with the `MockHSM`
pub(crate) struct Session {
    /// ID of the session
    pub id: SessionId,

    /// Card challenge for this session
    pub card_challenge: Challenge,

    /// Encrypted channel
    pub channel: Channel,
}

impl Session {
    /// Create a new session
    pub fn new(id: SessionId, card_challenge: Challenge, channel: Channel) -> Self {
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
