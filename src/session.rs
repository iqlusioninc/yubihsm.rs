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
use std::{
    panic::{self, AssertUnwindSafe},
    time::{Duration, Instant},
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

        let command = self.secure_channel()?.authenticate_session()?;
        let response = self.send_message(command)?;

        if let Err(e) = self
            .secure_channel()?
            .finish_authenticate_session(&response)
        {
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

    /// Get the underlying channel or return an error
    fn secure_channel(&mut self) -> Result<&mut SecureChannel, Error> {
        self.secure_channel
            .as_mut()
            .ok_or_else(|| format_err!(ErrorKind::ClosedError, "session is already closed").into())
    }
}

impl Drop for Session {
    /// Make a best effort to close the session if it's still healthy
    fn drop(&mut self) {
        // Only attempt to close the session if we have an active secure
        // channel and our session hasn't already timed out
        if self.secure_channel.is_none() || self.is_timed_out() {
            return;
        }

        session_debug!(self, "closing dropped session");

        // TODO: ensure we're really unwind safe.
        // This should still be better than panicking in a drop handler, hopefully
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            self.send_command(&CloseSessionCommand {}).unwrap()
        }));

        if let Err(err) = result {
            // Attempt to extract the error message from the `Any` returned from `catch_unwind`
            let msg = err
                .downcast_ref::<String>()
                .map(AsRef::as_ref)
                .or_else(|| err.downcast_ref::<&str>().cloned())
                .unwrap_or("unknown cause!");

            error!(
                "session={} panic closing dropped session: {}",
                self.id.to_u8(),
                msg
            );
        }
    }
}
