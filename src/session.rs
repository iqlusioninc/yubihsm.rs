//! `YubiHSM2` sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

use byteorder::{BigEndian, WriteBytesExt};
use connector::Connector;
use failure::Error;
use securechannel::{Challenge, Channel, Command, CommandType, Cryptogram, Response, StaticKeys,
                    CHALLENGE_SIZE};
use super::{KeyId, Object, SessionId};

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

    /// Protocol error occurred
    #[fail(display = "protocol error: {}", description)]
    ProtocolError {
        /// Details about the protocol error
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

        let command = Command::new(CommandType::CreateSession, command_data);
        let response = connector.send_command(command)?;

        if response.data.len() != CHALLENGE_SIZE * 2 {
            fail!(
                SessionError::CreateFailed,
                "invalid response length {} (expected {})",
                response.data.len(),
                CHALLENGE_SIZE * 2
            );
        }

        let id = response
            .session_id
            .ok_or_else(|| err!(SessionError::CreateFailed, "no session ID in response"))?;

        let card_challenge = Challenge::from_slice(&response.data[..CHALLENGE_SIZE]);
        let channel = Channel::new(id, static_keys, host_challenge, &card_challenge);
        let expected_card_cryptogram = channel.card_cryptogram();
        let actual_card_cryptogram = Cryptogram::from_slice(&response.data[CHALLENGE_SIZE..]);

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

    /// Get the current session ID
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Have the card echo an input message
    pub fn echo(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let command = Command::new(CommandType::Echo, msg);
        let response = self.send_encrypted_command(command)?;
        Ok(response.data)
    }

    /// List objects visible from the current session
    pub fn list_objects(&mut self) -> Result<Vec<Object>, Error> {
        // TODO: support for filtering objects
        let command = Command::new(CommandType::ListObjects, vec![]);
        let response = self.send_encrypted_command(command)?;

        let mut objects = Vec::with_capacity(response.data.len() / 4);

        for object_data in response.data.chunks(4) {
            objects.push(Object::from_list_response(object_data)?);
        }

        Ok(objects)
    }

    /// Authenticate the current session with the `YubiHSM2`
    fn authenticate(&mut self) -> Result<(), Error> {
        let command = self.channel.authenticate_session()?;
        let response = self.connector.send_command(command)?;
        self.channel.finish_authenticate_session(&response)
    }

    /// Encrypt a command and send it to the card, then authenticate and
    /// decrypt the response
    fn send_encrypted_command(&mut self, plaintext_cmd: Command) -> Result<Response, Error> {
        let encrypted_cmd = self.channel.encrypt_command(plaintext_cmd)?;
        let encrypted_response = self.connector.send_command(encrypted_cmd)?;
        self.channel.decrypt_response(encrypted_response)
    }
}
