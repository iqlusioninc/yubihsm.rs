//! `YubiHSM2` sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

mod error;

use failure::Error;

use commands::*;
use connector::Connector;
#[cfg(feature = "reqwest-connector")]
use connector::ReqwestConnector;
use responses::*;
use securechannel::{Challenge, Channel, CommandMessage, ResponseCode, ResponseMessage, StaticKeys};
use serializers::deserialize;
use super::{Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectType, SessionId};
pub use self::error::SessionError;

/// Salt value to use with PBKDF2 when deriving static keys from a password
pub const PBKDF2_SALT: &[u8] = b"Yubico";

/// Number of PBKDF2 iterations to perform when deriving static keys
pub const PBKDF2_ITERATIONS: usize = 10_000;

/// Status message returned from healthy connectors
const CONNECTOR_STATUS_OK: &str = "OK";

/// Type alias for a session with the default connector type
#[cfg(feature = "reqwest-connector")]
pub type Session = AbstractSession<ReqwestConnector>;

/// Encrypted session with the `YubiHSM2`
///
/// Generic over connector types in case a different one needs to be swapped in
pub struct AbstractSession<C: Connector> {
    /// ID of this session
    id: SessionId,

    /// Encrypted channel to the HSM
    channel: Channel,

    /// Connector to send messages through
    connector: C,

    /// Optional cached static keys for reconnecting lost sessions
    // TODO: session reconnect support
    #[allow(dead_code)]
    static_keys: Option<StaticKeys>,
}

impl<C: Connector> AbstractSession<C> {
    /// Open a new session to the HSM, authenticating with the given keypair
    pub fn create(
        connector_url: &str,
        auth_key_id: ObjectId,
        static_keys: StaticKeys,
        reconnect: bool,
    ) -> Result<Self, Error> {
        let connector = C::open(connector_url)?;
        let status = connector.status()?;

        if status.message != CONNECTOR_STATUS_OK {
            fail!(
                SessionError::CreateFailed,
                "bad status response from {}: {}",
                connector_url,
                status.message
            );
        }

        let host_challenge = Challenge::random();

        Self::new(
            connector,
            &host_challenge,
            auth_key_id,
            static_keys,
            reconnect,
        )
    }

    /// Open a new session to the HSM, authenticating with a given password
    pub fn create_from_password(
        connector_url: &str,
        auth_key_id: ObjectId,
        password: &str,
        reconnect: bool,
    ) -> Result<Self, Error> {
        Self::create(
            connector_url,
            auth_key_id,
            StaticKeys::derive_from_password(password.as_bytes(), PBKDF2_SALT, PBKDF2_ITERATIONS),
            reconnect,
        )
    }

    /// Create a new encrypted session using the given connector, YubiHSM2 auth key ID, and
    /// static identity keys
    pub fn new(
        connector: C,
        host_challenge: &Challenge,
        auth_key_id: ObjectId,
        static_keys: StaticKeys,
        reconnect: bool,
    ) -> Result<Self, Error> {
        let command_message: CommandMessage = CreateSessionCommand {
            auth_key_id,
            host_challenge: *host_challenge,
        }.into();

        let response_message =
            ResponseMessage::parse(connector.send_command(command_message.into())?)?;

        if response_message.is_err() {
            fail!(
                SessionError::ResponseError,
                "HSM error: {:?}",
                response_message.code
            );
        }

        if response_message.command().unwrap() != CommandType::CreateSession {
            fail!(
                SessionError::ProtocolError,
                "command type mismatch: expected {:?}, got {:?}",
                CommandType::CreateSession,
                response_message.command().unwrap()
            );
        }

        let session_id = response_message
            .session_id
            .ok_or_else(|| err!(SessionError::CreateFailed, "no session ID in response"))?;

        let response: CreateSessionResponse = deserialize(response_message.data.as_ref())?;

        let channel = Channel::new(
            session_id,
            &static_keys,
            host_challenge,
            &response.card_challenge,
        );

        // NOTE: Cryptogram implements constant-time equality comparison
        if channel.card_cryptogram() != response.card_cryptogram {
            fail!(SessionError::AuthFailed, "card cryptogram mismatch!");
        }

        let static_keys_option = if reconnect { Some(static_keys) } else { None };

        let mut session = Self {
            id: session_id,
            channel,
            connector,
            static_keys: static_keys_option,
        };

        session.authenticate()?;
        Ok(session)
    }

    /// Blink the YubiHSM2's LEDs (to identify it) for the given number of seconds
    pub fn blink(&mut self, num_seconds: u8) -> Result<BlinkResponse, Error> {
        self.send_encrypted_command(BlinkCommand { num_seconds })
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
        let response = self.send_command(command)?;
        self.channel.finish_authenticate_session(&response)
    }

    /// Send a command message to the YubiHSM2 and parse the response
    /// POST /connector/api with a given command message
    fn send_command(&self, cmd: CommandMessage) -> Result<ResponseMessage, Error> {
        let cmd_type = cmd.command_type;

        // TODO: handle reconnecting when sessions are lost
        let response_bytes = self.connector.send_command(cmd.into())?;
        let response = ResponseMessage::parse(response_bytes)?;

        if response.is_err() {
            fail!(
                SessionError::ResponseError,
                "HSM error: {:?}",
                response.code
            );
        }

        if response.command().unwrap() != cmd_type {
            fail!(
                SessionError::ProtocolError,
                "command type mismatch: expected {:?}, got {:?}",
                cmd_type,
                response.command().unwrap()
            );
        }

        Ok(response)
    }

    /// Encrypt a command and send it to the card, then authenticate and
    /// decrypt the response
    fn send_encrypted_command<T: Command>(&mut self, command: T) -> Result<T::ResponseType, Error> {
        let plaintext_cmd = command.into();
        let encrypted_cmd = self.channel.encrypt_command(plaintext_cmd)?;

        let encrypted_response = self.send_command(encrypted_cmd)?;
        let response = self.channel.decrypt_response(encrypted_response)?;

        if response.is_err() {
            // TODO: factor this into ResponseMessage or ResponseCode?
            let description = match response.code {
                ResponseCode::MemoryError => "HSM memory error (missing object?)".to_owned(),
                other => format!("{:?}", other),
            };

            fail!(SessionError::ResponseError, description);
        }

        if response.command().unwrap() != T::COMMAND_TYPE {
            fail!(
                SessionError::ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                T::COMMAND_TYPE,
                response.command().unwrap()
            );
        }

        deserialize(response.data.as_ref())
    }
}
