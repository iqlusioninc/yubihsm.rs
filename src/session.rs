//! Authenticated/encrypted sessions with the HSM.
//!
//! For more information, see:
//! <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

#[macro_use]
mod macros;

pub(crate) mod commands;
mod error;
mod guard;
mod id;
pub(crate) mod securechannel;
mod timeout;

pub use self::{
    error::{Error, ErrorKind},
    guard::Guard,
    id::Id,
    securechannel::{Challenge, Context, SessionKeys},
    timeout::Timeout,
};

use self::{commands::CloseSessionCommand, securechannel::SecureChannel};
use crate::{
    authentication::Credentials,
    command::{self, Command},
    connector::Connector,
    device, response,
    serialization::deserialize,
};
use std::time::{Duration, Instant};

#[cfg(feature = "yubihsm-auth")]
use crate::object;

/// Timeout fuzz factor: to avoid races/skew with the YubiHSM's clock,
/// we consider sessions to be timed out slightly earlier than the actual
/// timeout. This should (hopefully) ensure we always time out first,
/// and therefore generate appropriate timeout-related errors rather
/// than opaque "lost connection to HSM"-style errors.
const TIMEOUT_FUZZ_FACTOR: Duration = Duration::from_secs(1);

/// Session created on the device for which we do not
/// have credentials for yet.
///
/// This is used for YubiHSM Auth scheme support.
#[cfg(feature = "yubihsm-auth")]
pub struct PendingSession {
    ///// HSM Public key
    //card_public_key: PublicKey,
    /// Connector which communicates with the HSM (HTTP or USB)
    connector: Connector,

    /// Session creation timestamp
    created_at: Instant,

    /// Timestamp when this session was last active
    last_active: Instant,

    /// Inactivity timeout for this session
    timeout: Timeout,

    /// Challenge generate by the HSM.
    hsm_challenge: Challenge,

    /// ID for this session
    id: Id,

    context: Context,
}

#[cfg(feature = "yubihsm-auth")]
impl PendingSession {
    /// Creates a new session with the device.
    pub fn new(
        connector: Connector,
        timeout: Timeout,
        authentication_key_id: object::Id,
        host_challenge: Challenge,
    ) -> Result<Self, Error> {
        let (id, session_response) =
            SecureChannel::create(&connector, authentication_key_id, host_challenge)?;

        let hsm_challenge = session_response.card_challenge;
        let context = Context::from_challenges(host_challenge, hsm_challenge);

        let created_at = Instant::now();
        let last_active = Instant::now();

        Ok(PendingSession {
            id,
            connector,
            created_at,
            last_active,
            timeout,
            context,
            hsm_challenge,
        })
    }

    /// Create the session with the provided session keys
    pub fn realize(self, session_keys: SessionKeys) -> Result<Session, Error> {
        let secure_channel = Some(SecureChannel::with_session_keys(
            self.id,
            self.context,
            session_keys,
        ));

        let mut session = Session {
            id: self.id,
            secure_channel,
            connector: self.connector,
            created_at: self.created_at,
            last_active: self.last_active,
            timeout: self.timeout,
        };

        let response = session.start_authenticate()?;
        session.finish_authenticate_session(&response)?;

        Ok(session)
    }

    /// Return the challenge emitted by the HSM when opening the session
    pub fn get_challenge(&self) -> Challenge {
        self.hsm_challenge
    }

    /// Return the id of the session
    pub fn id(&self) -> Id {
        self.id
    }
}

/// Authenticated and encrypted (SCP03) `Session` with the HSM. A `Session` is
/// needed to perform any command.
///
/// `Session`s are automatically closed on `Drop`, releasing HSM session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Session {
    /// ID for this session
    id: Id,

    /// Connector which communicates with the HSM (HTTP or USB)
    connector: Connector,

    /// Encrypted channel (SCP03) to the HSM
    secure_channel: Option<SecureChannel>,

    /// Session creation timestamp
    created_at: Instant,

    /// Timestamp when this session was last active
    last_active: Instant,

    /// Inactivity timeout for this session
    timeout: Timeout,
}

impl Session {
    /// Connect to the HSM using the given configuration and credentials
    pub(super) fn open(
        connector: Connector,
        credentials: &Credentials,
        timeout: Timeout,
    ) -> Result<Self, Error> {
        ensure!(
            timeout.duration() > TIMEOUT_FUZZ_FACTOR,
            ErrorKind::CreateFailed,
            "timeout too low: must be longer than {:?}",
            TIMEOUT_FUZZ_FACTOR
        );

        let channel = SecureChannel::open(&connector, credentials)?;
        let now = Instant::now();

        let mut session = Session {
            id: channel.id(),
            connector,
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
    pub fn id(&self) -> Id {
        self.id
    }

    /// How long has this session been open?
    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Number of messages sent during this session
    pub fn messages_sent(&self) -> Result<usize, Error> {
        self.secure_channel
            .as_ref()
            .ok_or_else(|| format_err!(ErrorKind::ClosedError, "session is already closed").into())
            .map(SecureChannel::counter)
    }

    /// Has this session timed out?
    pub fn is_timed_out(&self) -> bool {
        let idle_time = Instant::now().duration_since(self.last_active);
        let timeout_with_fuzz = self.timeout.duration() - TIMEOUT_FUZZ_FACTOR;
        idle_time >= timeout_with_fuzz
    }

    /// Close this session, consuming it in the process.
    pub fn close(mut self) -> Result<(), Error> {
        // Only attempt to close the session if we have an active secure
        // channel and our session hasn't already timed out
        if self.secure_channel.is_none() || self.is_timed_out() {
            return Ok(());
        }

        session_debug!(self, "closing session");
        self.send_command(&CloseSessionCommand {})?;
        Ok(())
    }

    /// Abort this session, terminating it without closing it
    pub(crate) fn abort(&mut self) {
        self.secure_channel = None;
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(crate) fn send_command<C: Command>(
        &mut self,
        command: &C,
    ) -> Result<C::ResponseType, Error> {
        let plaintext_cmd = command::Message::from(command);
        let cmd_type = plaintext_cmd.command_type;

        let encrypted_cmd = self
            .secure_channel()?
            .encrypt_command(plaintext_cmd)
            .map_err(|e| {
                // Abort the session in the event of any cryptographic errors
                self.abort();
                e
            })?;

        let uuid = encrypted_cmd.uuid;
        session_debug!(
            self,
            "n={} uuid={} cmd={:?}",
            self.messages_sent()?,
            uuid,
            C::COMMAND_CODE
        );

        let encrypted_response = self.send_message(encrypted_cmd)?;

        let response = self
            .secure_channel()?
            .decrypt_response(encrypted_response)
            .map_err(|e| {
                // Abort the session in the event of any cryptographic errors
                self.abort();
                e
            })?;

        if response.is_err() {
            if let Some(kind) = device::ErrorKind::from_response_message(&response) {
                session_debug!(self, "uuid={} failed={:?} error={:?}", uuid, cmd_type, kind);
                return Err(kind.into());
            } else {
                session_debug!(self, "uuid={} failed={:?} error=unknown", uuid, cmd_type);
                fail!(ErrorKind::ResponseError, "{:?} failed: HSM error", cmd_type);
            }
        }

        if response.command() != Some(C::COMMAND_CODE) {
            fail!(
                ErrorKind::ResponseError,
                "bad command type in response: {:?} (expected {:?})",
                response.command(),
                C::COMMAND_CODE,
            );
        }

        deserialize(response.data.as_ref()).map_err(Into::into)
    }

    /// Send a command message to the HSM and parse the response
    fn send_message(&mut self, cmd: command::Message) -> Result<response::Message, Error> {
        let cmd_type = cmd.command_type;
        let uuid = cmd.uuid;
        self.last_active = Instant::now();

        // We log the plaintext of all `SessionMessage` commands, so ignore those
        if cmd_type != command::Code::SessionMessage {
            session_debug!(
                self,
                "n={} uuid={} msg={:?}",
                self.messages_sent()?,
                &uuid,
                cmd_type
            );
        }

        let response = match self.connector.send_message(uuid, cmd.into()) {
            Ok(response_bytes) => response::Message::parse(response_bytes)?,
            Err(e) => {
                // Abort the session in the event of errors
                self.abort();
                return Err(e.into());
            }
        };

        if response.is_err() {
            session_error!(self, "uuid={} error={:?}", &uuid, response.code);
            fail!(
                ErrorKind::ResponseError,
                "HSM error (session: {})",
                self.id().to_u8(),
            );
        }

        Ok(response)
    }

    /// Authenticate the current session with the HSM
    fn authenticate(&mut self, credentials: &Credentials) -> Result<(), Error> {
        session_debug!(
            self,
            "command={:?} key={}",
            command::Code::AuthenticateSession,
            credentials.authentication_key_id
        );

        let response = self.start_authenticate()?;

        if let Err(e) = self.finish_authenticate_session(&response) {
            session_error!(
                self,
                "failed={:?} key={} err={:?}",
                command::Code::AuthenticateSession,
                credentials.authentication_key_id,
                e.to_string()
            );

            return Err(e);
        }

        session_debug!(self, "auth=OK key={}", credentials.authentication_key_id);
        Ok(())
    }

    /// Send the message to the card to start authentication
    fn start_authenticate(&mut self) -> Result<response::Message, Error> {
        let command = self.secure_channel()?.authenticate_session()?;
        self.send_message(command)
    }

    /// Read authenticate session message from the card
    fn finish_authenticate_session(&mut self, response: &response::Message) -> Result<(), Error> {
        self.secure_channel()?.finish_authenticate_session(response)
    }

    /// Get the underlying channel or return an error
    fn secure_channel(&mut self) -> Result<&mut SecureChannel, Error> {
        self.secure_channel
            .as_mut()
            .ok_or_else(|| format_err!(ErrorKind::ClosedError, "session is already closed").into())
    }

    /// Get the underlying connector used by this session
    pub(crate) fn connector(&self) -> Connector {
        self.connector.clone()
    }
}
