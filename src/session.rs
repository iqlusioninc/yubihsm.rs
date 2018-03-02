//! `YubiHSM2` sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

use byteorder::{BigEndian, WriteBytesExt};
use commands::{Command, DeleteObjectCommand, EchoCommand, GenAsymmetricKeyCommand,
               GetObjectInfoCommand, ListObjectsCommand};
use connector::Connector;
use failure::Error;
use responses::{DeleteObjectResponse, EchoResponse, GenAsymmetricKeyResponse,
                GetObjectInfoResponse, ListObjectsResponse, Response};
use securechannel::{Challenge, Channel, CommandMessage, CommandType, Cryptogram, StaticKeys,
                    CHALLENGE_SIZE};
use super::{Algorithm, Capability, Domain, ObjectId, ObjectLabel, ObjectType, SessionId};

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

    /// HSM returned an error response
    #[fail(display = "error response from HSM: {}", description)]
    ResponseError {
        /// Description of the bad response we received
        description: String,
    },
}

impl<'a> Session<'a> {
    /// Create a new encrypted session using the given auth key and password
    pub fn new(
        connector: &'a Connector,
        host_challenge: &Challenge,
        auth_key_id: ObjectId,
        static_keys: &StaticKeys,
    ) -> Result<Self, Error> {
        let mut cmd_data = Vec::with_capacity(10);
        cmd_data.write_u16::<BigEndian>(auth_key_id).unwrap();
        cmd_data.extend_from_slice(host_challenge.as_slice());

        let command = CommandMessage::new(CommandType::CreateSession, cmd_data);
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

    /// Delete an object of the given ID and type
    pub fn delete_object(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
    ) -> Result<DeleteObjectResponse, Error> {
        self.send_encrypted_command(DeleteObjectCommand {
            object_id,
            object_type,
        })
    }

    /// Have the card echo an input message
    pub fn echo<T>(&mut self, message: T) -> Result<EchoResponse, Error>
    where
        T: Into<Vec<u8>>,
    {
        self.send_encrypted_command(EchoCommand {
            message: message.into(),
        })
    }

    /// Generate a new asymmetric key within the `YubiHSM2`
    pub fn generate_asymmetric_key(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: &[Domain],
        capabilities: &[Capability],
        algorithm: Algorithm,
    ) -> Result<GenAsymmetricKeyResponse, Error> {
        self.send_encrypted_command(GenAsymmetricKeyCommand {
            key_id,
            label,
            domains: domains.into(),
            capabilities: capabilities.into(),
            algorithm,
        })
    }

    /// Get information about an object
    pub fn get_object_info(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
    ) -> Result<GetObjectInfoResponse, Error> {
        self.send_encrypted_command(GetObjectInfoCommand {
            object_id,
            object_type,
        })
    }

    /// Get the current session ID
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// List objects visible from the current session
    pub fn list_objects(&mut self) -> Result<ListObjectsResponse, Error> {
        // TODO: support for filtering objects
        self.send_encrypted_command(ListObjectsCommand {})
    }

    /// Authenticate the current session with the `YubiHSM2`
    fn authenticate(&mut self) -> Result<(), Error> {
        let command = self.channel.authenticate_session()?;
        let response = self.connector.send_command(command)?;
        self.channel.finish_authenticate_session(&response)
    }

    /// Encrypt a command and send it to the card, then authenticate and
    /// decrypt the response
    fn send_encrypted_command<C: Command>(&mut self, command: C) -> Result<C::ResponseType, Error> {
        let plaintext_cmd = command.into();
        let encrypted_cmd = self.channel.encrypt_command(plaintext_cmd)?;
        let encrypted_response = self.connector.send_command(encrypted_cmd)?;
        let response = self.channel.decrypt_response(encrypted_response)?;

        if response.is_err() {
            fail!(SessionError::ResponseError, "{:?}", response.code);
        }

        if response.command().unwrap() != C::COMMAND_TYPE {
            fail!(
                SessionError::ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                C::COMMAND_TYPE,
                response.command().unwrap()
            );
        }

        C::ResponseType::parse(response.data)
    }
}
