//! `YubiHSM2` sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

use byteorder::{BigEndian, WriteBytesExt};
use connector::Connector;
use failure::Error;
use securechannel::{Challenge, Channel, Command, CommandType, Cryptogram, StaticKeys,
                    CHALLENGE_SIZE};
use super::{KeyId, SessionId};

/// Encrypted session with the `YubiHSM2`
pub struct Session<'a> {
    id: SessionId,
    channel: Channel,
    connector: &'a Connector,
}

/// Session-related errors
#[derive(Debug, Fail)]
pub enum SessionError {
    /// Couldn't create session
    #[fail(display = "couldn't create session: {}", description)]
    CreateFailed {
        /// Description of why we couldn't create the session
        description: String,
    },

    /// Couldn't authenticate session
    #[fail(display = "authentication failed: {}", description)]
    AuthFailed {
        /// Details about the authentication failure
        description: String,
    },
}

impl<'a> Session<'a> {
    /// Create a new encrypted session using the given auth key and password
    pub fn new(
        connector: &'a Connector,
        host_challenge: &Challenge,
        auth_key_id: KeyId,
        static_keys: &StaticKeys,
    ) -> Result<Self, Error> {
        let mut command_data = Vec::with_capacity(10);
        command_data.write_u16::<BigEndian>(auth_key_id)?;
        command_data.extend_from_slice(host_challenge.as_slice());

        let command = Command::new(CommandType::CreateSession, &command_data);
        let response = connector.command(command)?;

        if response.is_err() {
            fail!(
                SessionError::CreateFailed,
                "HSM error: {:?}",
                response.code()
            );
        }

        let response_body = response.body();
        if response_body.len() != 1 + CHALLENGE_SIZE * 2 {
            fail!(
                SessionError::CreateFailed,
                "invalid response length {} (expected {})",
                response.body().len(),
                1 + CHALLENGE_SIZE * 2
            );
        }

        let id = SessionId::new(response_body[0])?;
        let card_challenge = Challenge::from_slice(&response_body[1..9]);
        let channel = Channel::new(id, static_keys, host_challenge, &card_challenge);
        let expected_card_cryptogram = channel.card_cryptogram();
        let actual_card_cryptogram = Cryptogram::from_slice(&response_body[9..17]);

        if expected_card_cryptogram != actual_card_cryptogram {
            fail!(SessionError::AuthFailed, "card cryptogram mismatch!");
        }

        let mut session = Self {
            id,
            channel,
            connector,
        };

        session.authenticate()?;
        Ok(session)
    }

    /// Authenticate the current session with the `YubiHSM2`
    fn authenticate(&mut self) -> Result<(), Error> {
        let command = self.channel.authenticate_session()?;
        let response = self.connector.command(command)?;
        self.channel.finish_authenticate_session(&response)
    }

    /// Get the current session ID
    pub fn id(&self) -> SessionId {
        self.id
    }
}
