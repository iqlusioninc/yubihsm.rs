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
    securechannel::MAX_COMMANDS_PER_SESSION,
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

    /// Close this session, telling the HSM to release its resources rather
    /// than waiting for the session to time out.
    ///
    /// Sessions are also closed automatically on [`Drop`], so calling this is
    /// only necessary when you want to observe any error that occurs while
    /// closing. Closing an already-closed or timed-out session is a no-op.
    ///
    /// This is reachable through [`Client::session`][crate::Client::session],
    /// which derefs mutably to `Session`:
    ///
    /// ```no_run
    /// # fn example(client: &yubihsm::Client) -> Result<(), yubihsm::client::Error> {
    /// client.session()?.close()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn close(&mut self) -> Result<(), Error> {
        // Only close a channel that actually reached `Authenticated`.
        //
        // If `Session::open` fails during authentication -- the device rejects
        // `AuthenticateSession`, or answers it with unexpected data -- the
        // channel is left unauthenticated or terminated but still present. It
        // cannot encrypt the close command, and attempting it trips
        // `encrypt_command`'s assertion inside this destructor. There is also
        // nothing to release: the HSM never regarded the session as open.
        let authenticated = self
            .secure_channel
            .as_ref()
            .is_some_and(SecureChannel::is_authenticated);

        if !authenticated || self.is_timed_out() {
            return Ok(());
        }

        session_debug!(self, "closing session");
        let result = self.send_command(&CloseSessionCommand {});

        // Whether or not the HSM acknowledged it, this channel is finished.
        // Clearing it also stops the `Drop` handler from trying again.
        self.abort();

        result.map(|_| ())
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
        let plaintext_msg = command.to_message()?;
        let cmd_type = plaintext_msg.command_type;

        let encrypted_msg = self
            .secure_channel()?
            .encrypt_command(plaintext_msg)
            .inspect_err(|_| {
                // Abort the session in the event of any cryptographic errors
                self.abort();
            })?;

        let uuid = encrypted_msg.uuid;
        session_debug!(
            self,
            "n={} uuid={} cmd={:?}",
            self.messages_sent()?,
            uuid,
            C::COMMAND_CODE
        );

        let encrypted_response = self.send_message(encrypted_msg)?;

        let response = self
            .secure_channel()?
            .decrypt_response(encrypted_response)
            .inspect_err(|_| {
                // Abort the session in the event of any cryptographic errors
                self.abort();
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
        self.last_active = Instant::now();

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
    /// Make a best effort to close the session if it's still healthy.
    ///
    /// Without this, sessions are only released when the HSM times them out,
    /// which exhausts the device's limited pool of concurrent sessions.
    fn drop(&mut self) {
        // Never touch the transport while unwinding.
        //
        // `Connector::send_message` locks with `lock().unwrap()`. If a panic
        // poisoned that mutex — including a panic raised *while* it was held —
        // closing here would panic a second time inside a destructor, which
        // aborts the process. A recoverable panic must not become an abort just
        // because a session went out of scope on the way out.
        //
        // The session is still released: the HSM times it out on its own.
        if std::thread::panicking() {
            self.abort();
            return;
        }

        // `close` already short-circuits on a closed or timed-out session.
        //
        // Errors are logged rather than propagated: a destructor has nowhere
        // to return them, and failing to notify the HSM is recoverable — the
        // session times out on its own.
        if let Err(err) = self.close() {
            error!(
                "session={} error closing dropped session: {}",
                self.id.to_u8(),
                err
            );
        }
    }
}

#[cfg(all(test, feature = "mockhsm", feature = "passwords"))]
mod tests {
    use super::*;
    use crate::authentication;
    use crate::session::securechannel::Challenge;

    /// A `Session` whose channel never authenticated must not try to close
    /// itself on drop.
    ///
    /// When `Session::open` fails during authentication -- the device rejects
    /// `AuthenticateSession`, or answers it with unexpected data -- the channel
    /// is left present but unauthenticated. Closing it reaches
    /// `SecureChannel::encrypt_command`, which asserts on the security level,
    /// so the destructor panics and turns a returned error into a crash.
    #[test]
    fn dropping_an_unauthenticated_session_does_not_panic() {
        let channel = SecureChannel::new(
            Id::from_u8(1).unwrap(),
            &authentication::Key::default(),
            Challenge::new(),
            Challenge::new(),
        );

        assert!(
            !channel.is_authenticated(),
            "a freshly created channel must not be authenticated"
        );

        let now = Instant::now();
        let session = Session {
            id: channel.id(),
            connector: Connector::mockhsm(),
            secure_channel: Some(channel),
            created_at: now,
            last_active: now,
            timeout: Timeout::default(),
        };

        // The assertion under test is that this does not panic.
        drop(session);
    }

    /// The same session must also report a clean `close()` rather than panicking.
    #[test]
    fn closing_an_unauthenticated_session_is_a_no_op() {
        let channel = SecureChannel::new(
            Id::from_u8(1).unwrap(),
            &authentication::Key::default(),
            Challenge::new(),
            Challenge::new(),
        );

        let now = Instant::now();
        let mut session = Session {
            id: channel.id(),
            connector: Connector::mockhsm(),
            secure_channel: Some(channel),
            created_at: now,
            last_active: now,
            timeout: Timeout::default(),
        };

        session.close().expect("closing must not error");
    }
}
