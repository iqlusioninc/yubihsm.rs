//! Encrypted connection to the HSM through a particular adapter

use subtle::ConstantTimeEq;

use super::{SessionError, SessionErrorKind::*};
use adapters::Adapter;
use commands::{create_session::create_session, Command, CommandType};
use credentials::Credentials;
use securechannel::{Challenge, CommandMessage, ResponseMessage, SecureChannel, SessionId};
use serializers::deserialize;

/// Encrypted connection to the HSM made through a particular adapter.
/// This type handles opening/closing adapters and creating encrypted
/// (SCP03) channels.
pub(super) struct Connection<A: Adapter> {
    /// Adapter which communicates with the HSM (HTTP or USB)
    adapter: A,

    /// Encrypted (SCP03) channel to the HSM
    secure_channel: Option<SecureChannel>,
}

impl<A: Adapter> Connection<A> {
    /// Connect to the HSM using the given configuration and credentials
    pub(super) fn open(
        config: &A::Config,
        credentials: &Credentials,
    ) -> Result<Self, SessionError> {
        let adapter = A::open(config)?;

        // Ensure the new connection is healthy
        if let Err(e) = adapter.healthcheck() {
            fail!(CreateFailed, e);
        }

        let host_challenge = Challenge::random();

        let (session_id, session_response) =
            create_session(&adapter, credentials.auth_key_id, host_challenge)?;

        let channel = SecureChannel::new(
            session_id,
            &credentials.auth_key,
            host_challenge,
            session_response.card_challenge,
        );

        if channel
            .card_cryptogram()
            .ct_eq(&session_response.card_cryptogram)
            .unwrap_u8()
            != 1
        {
            fail!(
                AuthFail,
                "(session: {}) card cryptogram mismatch!",
                channel.id().to_u8()
            );
        }

        let mut connection = Connection {
            adapter,
            secure_channel: Some(channel),
        };
        connection.authenticate(credentials)?;
        Ok(connection)
    }

    /// Get the current session ID (if we have an open session)
    #[inline]
    pub(super) fn id(&self) -> Option<SessionId> {
        self.secure_channel.as_ref().map(|c| c.id())
    }

    /// Borrow the underlying adapter
    pub(super) fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(super) fn send_command<T: Command>(
        &mut self,
        command: T,
    ) -> Result<T::ResponseType, SessionError> {
        let plaintext_cmd: CommandMessage = command.into();
        let cmd_type = plaintext_cmd.command_type;
        let encrypted_cmd = self.secure_channel()?.encrypt_command(plaintext_cmd)?;
        let uuid = encrypted_cmd.uuid;

        session_debug!(self, "uuid={} cmd={:?}", uuid, T::COMMAND_TYPE);

        let encrypted_response = self.send_message(encrypted_cmd)?;

        // For decryption we go straight to the connection's secure channel,
        // skipping checks of whether or not the connection is open, as we
        // have already completed all I/O.
        let response = self
            .secure_channel()?
            .decrypt_response(encrypted_response)
            .map_err(|e| {
                self.secure_channel = None;
                e
            })?;

        if response.is_err() {
            session_debug!(
                self,
                "uuid={} failed={:?} code={:?}",
                uuid,
                cmd_type,
                response.code
            );

            return Err(response.code.into());
        }

        if response.command() != Some(T::COMMAND_TYPE) {
            fail!(
                ResponseError,
                "bad command type in response: {:?} (expected {:?})",
                response.command(),
                T::COMMAND_TYPE,
            );
        }

        deserialize(response.data.as_ref()).map_err(|e| e.into())
    }

    /// Send a command message to the HSM and parse the response
    fn send_message(&mut self, cmd: CommandMessage) -> Result<ResponseMessage, SessionError> {
        let cmd_type = cmd.command_type;
        let uuid = cmd.uuid;

        session_debug!(self, "uuid={} command={:?}", &uuid, cmd_type);

        let response = match self.adapter.send_message(uuid, cmd.into()) {
            Ok(response_bytes) => ResponseMessage::parse(response_bytes)?,
            Err(e) => {
                self.secure_channel = None;
                return Err(e.into());
            }
        };

        if response.is_err() || response.command() != Some(cmd_type) {
            session_error!(self, "uuid={} error={:?}", &uuid, response.code);

            fail!(
                ResponseError,
                "HSM error (session: {})",
                self.id().unwrap().to_u8(),
            );
        }

        Ok(response)
    }

    /// Authenticate the current session with the HSM
    fn authenticate(&mut self, credentials: &Credentials) -> Result<(), SessionError> {
        session_debug!(
            self,
            "command={:?} key={}",
            CommandType::AuthSession,
            credentials.auth_key_id
        );

        let command = self.secure_channel()?.authenticate_session()?;
        let response = self.send_message(command)?;

        if let Err(e) = self
            .secure_channel()?
            .finish_authenticate_session(&response)
        {
            session_error!(
                self,
                "failed={:?} key={} err={:?}",
                CommandType::AuthSession,
                credentials.auth_key_id,
                e.to_string()
            );

            return Err(e.into());
        }

        session_debug!(self, "auth=OK key={}", credentials.auth_key_id);
        Ok(())
    }

    /// Get the underlying channel or return an error
    fn secure_channel(&mut self) -> Result<&mut SecureChannel, SessionError> {
        self.secure_channel
            .as_mut()
            .ok_or_else(|| err!(ClosedSessionError, "session is already closed"))
    }
}
