//! Encrypted connection to the HSM through a particular connection

use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

use command::{Command, CommandCode, CommandMessage};
use connector::{Connection, Connector};
use credentials::Credentials;
use error::HsmErrorKind;
use response::ResponseMessage;
use serialization::deserialize;

#[macro_use]
mod macros;

pub(crate) mod command;
mod error;
mod id;
pub(crate) mod securechannel;
mod timeout;

use self::command::close::*;
pub use self::id::SessionId;
use self::securechannel::{Challenge, SecureChannel};
use self::SessionErrorKind::*;
pub use self::{
    error::{SessionError, SessionErrorKind},
    timeout::SessionTimeout,
};

/// Timeout fuzz factor: to avoid races/skew with the YubiHSM's clock,
/// we consider sessions to be timed out slightly earlier than the actual
/// timeout. This should (hopefully) ensure we always time out first,
/// and therefore generate appropriate timeout-related errors rather
/// than opaque "lost connection to HSM"-style errors.
const TIMEOUT_FUZZ_FACTOR: Duration = Duration::from_secs(1);

/// Authenticated and encrypted (SCP03) `Session` with the HSM. A `Session` is
/// needed to perform any command.
///
/// `Session`s are automatically closed on `Drop`, releasing HSM session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Session {
    /// ID for this session
    id: SessionId,

    /// Connection which communicates with the HSM (HTTP or USB)
    connection: Box<Connection>,

    /// Encrypted channel (SCP03) to the HSM
    secure_channel: Option<SecureChannel>,

    /// Session creation timestamp
    created_at: Instant,

    /// Timestamp when this session was last active
    last_active: Instant,

    /// Inactivity timeout for this session
    timeout: SessionTimeout,
}

impl Session {
    /// Connect to the HSM using the given configuration and credentials
    pub(super) fn open(
        connector: &Connector,
        credentials: &Credentials,
        timeout: SessionTimeout,
    ) -> Result<Self, SessionError> {
        ensure!(
            timeout.duration() > TIMEOUT_FUZZ_FACTOR,
            CreateFailed,
            "timeout too low: must be longer than {:?}",
            TIMEOUT_FUZZ_FACTOR
        );

        // Ensure `Connector` is healthy before attempting to open `Session`
        connector.healthcheck()?;

        let connection = connector.connect()?;
        let host_challenge = Challenge::random();

        let (session_id, session_response) =
            command::create_session(&*connection, credentials.auth_key_id, host_challenge)?;

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

        let id = channel.id();
        let now = Instant::now();

        let mut session = Session {
            id,
            connection,
            secure_channel: Some(channel),
            created_at: now,
            last_active: now,
            timeout,
        };

        session.authenticate(credentials)?;
        Ok(session)
    }

    /// Is this `Session` still open?
    pub fn is_open(&self) -> bool {
        self.secure_channel.is_some() && !self.is_timed_out()
    }

    /// Session ID value (1-16)
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// How long has this session been open?
    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Number of messages sent during this session
    pub fn messages_sent(&self) -> Result<usize, SessionError> {
        self.secure_channel
            .as_ref()
            .ok_or_else(|| err!(ClosedSessionError, "session is already closed"))
            .map(SecureChannel::counter)
    }

    /// Has this session timed out?
    pub fn is_timed_out(&self) -> bool {
        let idle_time = Instant::now().duration_since(self.last_active);
        let timeout_with_fuzz = self.timeout.duration() - TIMEOUT_FUZZ_FACTOR;
        idle_time >= timeout_with_fuzz
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(crate) fn send_command<C: Command>(
        &mut self,
        command: C,
    ) -> Result<C::ResponseType, SessionError> {
        let plaintext_cmd: CommandMessage = command.into();
        let cmd_type = plaintext_cmd.command_type;
        let encrypted_cmd = self.secure_channel()?.encrypt_command(plaintext_cmd)?;
        let uuid = encrypted_cmd.uuid;

        session_debug!(self, "uuid={} cmd={:?}", uuid, C::COMMAND_CODE);

        let encrypted_response = self.send_message(encrypted_cmd)?;

        let response = self
            .secure_channel()?
            .decrypt_response(encrypted_response)
            .map_err(|e| {
                self.secure_channel = None;
                e
            })?;

        if response.is_err() {
            if let Some(kind) = HsmErrorKind::from_response_message(&response) {
                session_debug!(self, "uuid={} failed={:?} error={:?}", uuid, cmd_type, kind);
                return Err(kind.into());
            } else {
                session_debug!(self, "uuid={} failed={:?} error=unknown", uuid, cmd_type);
                fail!(ResponseError, "{:?} failed: HSM error", cmd_type);
            }
        }

        if response.command() != Some(C::COMMAND_CODE) {
            fail!(
                ResponseError,
                "bad command type in response: {:?} (expected {:?})",
                response.command(),
                C::COMMAND_CODE,
            );
        }

        deserialize(response.data.as_ref()).map_err(|e| e.into())
    }

    /// Send a command message to the HSM and parse the response
    fn send_message(&mut self, cmd: CommandMessage) -> Result<ResponseMessage, SessionError> {
        let cmd_type = cmd.command_type;
        let uuid = cmd.uuid;
        self.last_active = Instant::now();

        session_debug!(self, "uuid={} command={:?}", &uuid, cmd_type);

        let response = match self.connection.send_message(uuid, cmd.into()) {
            Ok(response_bytes) => ResponseMessage::parse(response_bytes)?,
            Err(e) => {
                self.secure_channel = None;
                return Err(e.into());
            }
        };

        if response.is_err() {
            session_error!(self, "uuid={} error={:?}", &uuid, response.code);
            fail!(ResponseError, "HSM error (session: {})", self.id().to_u8(),);
        }

        Ok(response)
    }

    /// Authenticate the current session with the HSM
    fn authenticate(&mut self, credentials: &Credentials) -> Result<(), SessionError> {
        session_debug!(
            self,
            "command={:?} key={}",
            CommandCode::AuthSession,
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
                CommandCode::AuthSession,
                credentials.auth_key_id,
                e.to_string()
            );

            return Err(e);
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

/// Close session automatically on drop
impl Drop for Session {
    /// Make a best effort to close the session
    ///
    /// NOTE: this runs the potential of panicking in a drop handler, which
    /// results in the following when it occurs (Aieee!):
    ///
    /// "thread panicked while panicking. aborting"
    ///
    /// Because of this, it's very important `send_encrypted_command` and
    /// everything it calls be panic-free.
    fn drop(&mut self) {
        // Don't do anything if the session already timed out
        if self.is_timed_out() {
            return;
        }

        session_debug!(self, "closing dropped session");

        if let Err(e) = self.send_command(CloseSessionCommand {}) {
            session_debug!(self, "error closing dropped session: {}", e);
        }
    }
}
