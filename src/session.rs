//! `YubiHSM2` sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

use commands::*;
use connector::Connector;
use failure::Error;
use responses::*;
use securechannel::{Challenge, Channel, ResponseCode, StaticKeys};
use serializers::deserialize;
use super::{Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectType, SessionId};

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
        let response_message = connector.send_command(
            CreateSessionCommand {
                auth_key_id,
                host_challenge: *host_challenge,
            }.into(),
        )?;

        let session_id = response_message
            .session_id
            .ok_or_else(|| err!(SessionError::CreateFailed, "no session ID in response"))?;

        let response: CreateSessionResponse = deserialize(response_message.data.as_ref())?;

        let channel = Channel::new(
            session_id,
            static_keys,
            host_challenge,
            &response.card_challenge,
        );

        // NOTE: Cryptogram implements constant-time equality comparison
        if channel.card_cryptogram() != response.card_cryptogram {
            fail!(SessionError::AuthFailed, "card cryptogram mismatch!");
        }

        let mut session = Self {
            id: session_id,
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
        domains: Domains,
        capabilities: Capabilities,
        algorithm: Algorithm,
    ) -> Result<GenAsymmetricKeyResponse, Error> {
        self.send_encrypted_command(GenAsymmetricKeyCommand {
            key_id,
            label,
            domains,
            capabilities,
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

    /// Get the public key for an asymmetric key stored on the device
    ///
    /// See `GetPubKeyResponse` for more information about public key formats
    pub fn get_pubkey(&mut self, key_id: ObjectId) -> Result<GetPubKeyResponse, Error> {
        self.send_encrypted_command(GetPubKeyCommand { key_id })
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

    /// Compute an Ed25519 signature with the given key ID
    pub fn sign_data_eddsa<T>(
        &mut self,
        key_id: ObjectId,
        data: T,
    ) -> Result<SignDataEdDSAResponse, Error>
    where
        T: Into<Vec<u8>>,
    {
        self.send_encrypted_command(SignDataEdDSACommand {
            key_id,
            data: data.into(),
        })
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
            // TODO: factor this into ResponseMessage or ResponseCode?
            let description = match response.code {
                ResponseCode::MemoryError => "HSM memory error (missing object?)".to_owned(),
                other => format!("{:?}", other),
            };

            fail!(SessionError::ResponseError, description);
        }

        if response.command().unwrap() != C::COMMAND_TYPE {
            fail!(
                SessionError::ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                C::COMMAND_TYPE,
                response.command().unwrap()
            );
        }

        deserialize(response.data.as_ref())
    }
}
