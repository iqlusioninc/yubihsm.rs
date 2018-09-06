use std::time::{Duration, Instant};

#[macro_use]
mod error;

pub(crate) mod connection;
mod timeout;

use self::connection::Connection;
use self::error::SessionErrorKind::*;
pub use self::{
    error::{SessionError, SessionErrorKind},
    timeout::SessionTimeout,
};
#[cfg(feature = "usb")]
use adapters::usb::UsbAdapter;
use adapters::{http::HttpAdapter, Adapter};
use commands::{close_session::CloseSessionCommand, Command};
use credentials::Credentials;
use securechannel::{CommandMessage, ResponseCode, SecureChannel, SessionId};
use serializers::deserialize;

/// Timeout fuzz factor: to avoid races/skew with the YubiHSM's clock,
/// we consider sessions to be timed out slightly earlier than the actual
/// timeout. This should (hopefully) ensure we always time out first.
const TIMEOUT_SKEW_INTERVAL: Duration = Duration::from_secs(1);

/// Write consistent `debug!(...) lines for sessions
macro_rules! session_debug {
    ($session:expr, $msg:expr) => {
        if let Some(session) = $session.id() {
            debug!("(session: {}) {}", session.to_u8(), $msg);
        } else {
            debug!("(session: none) {}", $msg);
        }
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        if let Some(session) = $session.id() {
            debug!(concat!("(session: {}) ", $fmt), session.to_u8(), $($arg)+);
        } else {
            debug!(concat!("(session: none) ", $fmt), $($arg)+);
        }
    };
}

/// Session with a YubiHSM connected through `yubihsm-connector`
pub type HttpSession = Session<HttpAdapter>;

/// Session with a YubiHSM
#[cfg(feature = "usb")]
pub type UsbSession = Session<UsbAdapter>;

/// Encrypted session with a YubiHSM.
/// A session is needed to perform any commands.
///
/// Sessions are eneric over `Adapter` types in case a different one needs to
/// be swapped in, which is primarily useful for substituting the `MockHSM`.
///
/// Sessions are automatically closed on `Drop`, releasing `YubiHSM2` session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Session<A: Adapter> {
    /// Connection to the HSM (low-level session state)
    pub(crate) connection: Connection<A>,

    /// Cached `Credentials`
    pub(crate) credentials: Option<Credentials>,

    /// Instant when the last command with the HSM was sent. Used for
    /// tracking session inactivity timeouts
    pub(crate) last_command_timestamp: Instant,

    /// Timeout to use for session inactivity
    pub(crate) timeout: SessionTimeout,
}

impl<A: Adapter> Session<A> {
    /// Create a new session, eagerly connecting to the YubiHSM
    pub fn create(
        config: A::Config,
        credentials: Credentials,
        reconnect: bool,
    ) -> Result<Self, SessionError> {
        let mut session = Self::new(config, credentials)?;
        session.open()?;

        // Clear credenials if reconnecting has been disabled
        if !reconnect {
            session.credentials = None;
        }

        Ok(session)
    }

    /// Initialize a new encrypted session, deferring actually establishing
    /// a session until `connect()` is called
    pub fn new(config: A::Config, credentials: Credentials) -> Result<Self, SessionError> {
        debug!("yubihsm: creating new session");

        let session = Self {
            connection: Connection::new(config),
            credentials: Some(credentials),
            last_command_timestamp: Instant::now(),
            timeout: SessionTimeout::default(),
        };

        Ok(session)
    }

    /// Connect to the YubiHSM
    pub fn open(&mut self) -> Result<(), SessionError> {
        self.connection.open(
            self.credentials
                .as_ref()
                .ok_or_else(|| err!(AuthFailed, "session reconnection disabled"))?,
        )?;

        self.last_command_timestamp = Instant::now();
        Ok(())
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> Option<SessionId> {
        self.connection.id()
    }

    /// Do we currently have an open session with the HSM?
    pub fn is_open(&self) -> bool {
        if !self.connection.is_open() {
            return false;
        }

        let time_since_last_command = Instant::now().duration_since(self.last_command_timestamp);

        // Make sure the session hasn't timed out
        if time_since_last_command > (self.timeout.duration() - TIMEOUT_SKEW_INTERVAL) {
            session_debug!(
                self,
                "session timed out after {} seconds (max {})",
                time_since_last_command.as_secs(),
                self.timeout.duration().as_secs()
            );
            return false;
        }

        true
    }

    /// Borrow the adapter for this session (if available)
    pub fn adapter(&mut self) -> Result<&A, SessionError> {
        self.connection.open_adapter()
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(crate) fn send_command<T: Command>(
        &mut self,
        command: T,
    ) -> Result<T::ResponseType, SessionError> {
        let plaintext_cmd: CommandMessage = command.into();
        let cmd_type = plaintext_cmd.command_type;
        let encrypted_cmd = self.secure_channel()?.encrypt_command(plaintext_cmd)?;
        let uuid = encrypted_cmd.uuid;

        session_debug!(self, "uuid={} cmd={:?}", uuid, T::COMMAND_TYPE);

        self.last_command_timestamp = Instant::now();
        let encrypted_response = self.connection.send_message(encrypted_cmd)?;

        // For decryption we go straight to the connection's secure channel,
        // skipping checks of whether or not the connection is open, as we
        // have already completed all I/O.
        let response = match self
            .connection
            .secure_channel()?
            .decrypt_response(encrypted_response)
        {
            Ok(resp) => resp,
            Err(e) => {
                // Cryptographic error. Terminate the current secure channel
                self.connection.close_secure_channel();
                return Err(e.into());
            }
        };

        session_debug!(
            self,
            "uuid={} resp={:?} length={}",
            uuid,
            response.code,
            response.data.len()
        );

        if response.is_err() {
            // TODO: factor this into ResponseMessage or ResponseCode?
            let description = match response.code {
                ResponseCode::MemoryError => {
                    "general HSM error (e.g. bad command params, missing object)".to_owned()
                }
                other => format!("{:?}", other),
            };

            session_debug!(
                self,
                "uuid={} failed={:?} code={:?} err=\"{}\"",
                uuid,
                cmd_type,
                response.code.to_u8(),
                &description
            );

            fail!(ResponseError, description);
        }

        if response.command().unwrap() != T::COMMAND_TYPE {
            fail!(
                ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                T::COMMAND_TYPE,
                response.command().unwrap()
            );
        }

        deserialize(response.data.as_ref()).map_err(|e| e.into())
    }

    /// Get the `SecureChannel` for this session
    fn secure_channel(&mut self) -> Result<&mut SecureChannel, SessionError> {
        // (Re)open the secure channel if we're in a disconnected state
        if !self.is_open() {
            self.connection.close_secure_channel();
            self.open()?;
        }

        self.connection.secure_channel()
    }
}

/// Close session automatically on drop
impl<A: Adapter> Drop for Session<A> {
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
        // Don't do anything if the session is presumed unhealthy
        if !self.is_open() {
            return;
        }

        session_debug!(self, "closing dropped session");

        if let Err(e) = self.send_command(CloseSessionCommand {}) {
            session_debug!(self, "error closing dropped session: {}", e);
        }
    }
}
