#[macro_use]
mod error;

use self::error::ClientErrorKind::*;
pub use self::error::{ClientError, ClientErrorKind};
use command::Command;
#[cfg(feature = "http")]
use connection::http::HttpConnection;
#[cfg(feature = "usb")]
use connection::usb::UsbConnection;
use connection::Connection;
use credentials::Credentials;
use session::{Session, SessionId, SessionTimeout};

/// Session with a YubiHSM connected through `yubihsm-connector`
#[cfg(feature = "http")]
pub type HttpClient = Client<HttpConnection>;

/// Session with a YubiHSM
#[cfg(feature = "usb")]
pub type UsbClient = Client<UsbConnection>;

/// Encrypted session with a YubiHSM.
/// A session is needed to perform any command.
///
/// Sessions are eneric over `Connection` types in case a different one needs to
/// be swapped in, which is primarily useful for substituting the `MockHsm`.
///
/// Sessions are automatically closed on `Drop`, releasing `YubiHSM2` session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Client<A: Connection> {
    /// Configuration for connecting to the HSM
    config: A::Config,

    /// Encrypted session with the HSM (if we have one open)
    session: Option<Session<A>>,

    /// Cached `Credentials` for reconnecting closed sessions
    credentials: Option<Credentials>,
}

impl<A: Connection> Client<A> {
    /// Create a new session, eagerly connecting to the YubiHSM
    pub fn create(
        config: A::Config,
        credentials: Credentials,
        reconnect: bool,
    ) -> Result<Self, ClientError> {
        let mut session = Self::new(config, credentials)?;
        session.open()?;

        // Clear credentials if reconnecting has been disabled
        if !reconnect {
            session.credentials = None;
        }

        Ok(session)
    }

    /// Initialize a new encrypted session, deferring actually establishing
    /// a session until `open()` is called
    pub fn new(config: A::Config, credentials: Credentials) -> Result<Self, ClientError> {
        let session = Self {
            config,
            session: None,
            credentials: Some(credentials),
        };

        Ok(session)
    }

    /// Connect to the YubiHSM (if we aren't already connected)
    pub fn open(&mut self) -> Result<(), ClientError> {
        self.session()?;
        Ok(())
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> Option<SessionId> {
        self.session.as_ref().and_then(|s| Some(s.id()))
    }

    /// Do we currently have an open session with the HSM?
    pub fn is_open(&self) -> bool {
        // TODO: ensure session hasn't timed out
        self.session.is_some()
    }

    /// Borrow the underlying connection (lazily initializing it) or return an error
    pub fn session(&mut self) -> Result<&mut Session<A>, ClientError> {
        if self.is_open() {
            return Ok(self.session.as_mut().unwrap());
        }

        // Clear any existing connection (i.e. make sure old connections are
        // dropped before opening new ones)
        self.session = None;

        let connection = Session::open(
            &self.config,
            self.credentials
                .as_ref()
                .ok_or_else(|| err!(AuthFail, "session reconnection disabled"))?,
            SessionTimeout::default(),
        )?;

        self.session = Some(connection);
        Ok(self.session.as_mut().unwrap())
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response
    pub(crate) fn send_command<T: Command>(
        &mut self,
        command: T,
    ) -> Result<T::ResponseType, ClientError> {
        Ok(self.session()?.send_command(command)?)
    }
}
