use std::time::{Duration, Instant};

#[macro_use]
mod error;

#[cfg(feature = "http")]
use adapters::http::HttpAdapter;
#[cfg(feature = "usb")]
use adapters::usb::UsbAdapter;
use adapters::Adapter;
use commands::{close_session::CloseSessionCommand, Command};
use credentials::Credentials;
use securechannel::SessionId;

/// Write consistent `debug!(...) lines for sessions
macro_rules! session_debug {
    ($session:expr, $msg:expr) => {
        if let Some(session) = $session.id() {
            debug!("session={} {}", session.to_u8(), $msg);
        } else {
            debug!("session=none {}", $msg);
        }
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        if let Some(session) = $session.id() {
            debug!(concat!("session={} ", $fmt), session.to_u8(), $($arg)+);
        } else {
            debug!(concat!("session=none ", $fmt), $($arg)+);
        }
    };
}

/// Write consistent `error!(...) lines for sessions
macro_rules! session_error {
    ($session:expr, $msg:expr) => {
        if let Some(session) = $session.id() {
            error!("session={} {}", session.to_u8(), $msg);
        } else {
            error!("session=none {}", $msg);
        }
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        if let Some(session) = $session.id() {
            error!(concat!("session={} ", $fmt), session.to_u8(), $($arg)+);
        } else {
            error!(concat!("session=none ", $fmt), $($arg)+);
        }
    };
}

pub(crate) mod connection;
mod timeout;

use self::connection::Connection;
use self::error::SessionErrorKind::*;
pub use self::{
    error::{SessionError, SessionErrorKind},
    timeout::SessionTimeout,
};

/// Timeout fuzz factor: to avoid races/skew with the YubiHSM's clock,
/// we consider sessions to be timed out slightly earlier than the actual
/// timeout. This should (hopefully) ensure we always time out first.
const TIMEOUT_SKEW_INTERVAL: Duration = Duration::from_secs(1);

/// Session with a YubiHSM connected through `yubihsm-connector`
#[cfg(feature = "http")]
pub type HttpSession = Session<HttpAdapter>;

/// Session with a YubiHSM
#[cfg(feature = "usb")]
pub type UsbSession = Session<UsbAdapter>;

/// Encrypted session with a YubiHSM.
/// A session is needed to perform any commands.
///
/// Sessions are eneric over `Adapter` types in case a different one needs to
/// be swapped in, which is primarily useful for substituting the `MockHsm`.
///
/// Sessions are automatically closed on `Drop`, releasing `YubiHSM2` session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Session<A: Adapter> {
    /// Configuration for connecting to the HSM
    config: A::Config,

    /// Connection to the HSM (low-level session state)
    connection: Option<Connection<A>>,

    /// Cached `Credentials`
    credentials: Option<Credentials>,

    /// Instant when the last command with the HSM was sent. Used for
    /// tracking session inactivity timeouts
    last_command_timestamp: Instant,

    /// Timeout to use for session inactivity
    timeout: SessionTimeout,
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

        // Clear credentials if reconnecting has been disabled
        if !reconnect {
            session.credentials = None;
        }

        Ok(session)
    }

    /// Initialize a new encrypted session, deferring actually establishing
    /// a session until `connect()` is called
    pub fn new(config: A::Config, credentials: Credentials) -> Result<Self, SessionError> {
        let session = Self {
            config,
            connection: None,
            credentials: Some(credentials),
            last_command_timestamp: Instant::now(),
            timeout: SessionTimeout::default(),
        };

        Ok(session)
    }

    /// Connect to the YubiHSM
    pub fn open(&mut self) -> Result<(), SessionError> {
        self.connection()?;
        Ok(())
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> Option<SessionId> {
        self.connection.as_ref().and_then(|ref c| c.id())
    }

    /// Do we currently have an open session with the HSM?
    pub fn is_open(&self) -> bool {
        if self.connection.is_none() {
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
        Ok(self.connection()?.adapter())
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(crate) fn send_command<T: Command>(
        &mut self,
        command: T,
    ) -> Result<T::ResponseType, SessionError> {
        let response = self.connection()?.send_command(command)?;
        self.last_command_timestamp = Instant::now();
        Ok(response)
    }

    /// Get the underlying connection or return an error
    fn connection(&mut self) -> Result<&mut Connection<A>, SessionError> {
        if self.is_open() {
            return Ok(self.connection.as_mut().unwrap());
        }

        // Clear any existing connection (i.e. make sure old connections are
        // dropped before opening new ones)
        self.connection = None;

        let connection = Connection::open(
            &self.config,
            self.credentials
                .as_ref()
                .ok_or_else(|| err!(AuthFail, "session reconnection disabled"))?,
        )?;

        self.connection = Some(connection);
        self.last_command_timestamp = Instant::now();
        Ok(self.connection.as_mut().unwrap())
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
