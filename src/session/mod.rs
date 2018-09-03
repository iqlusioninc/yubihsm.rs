use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

#[macro_use]
mod error;

pub use self::error::{SessionError, SessionErrorKind};
use adapters::{Adapter, HttpAdapter, HttpConfig};
use auth_key::AuthKey;
use commands::{close_session::CloseSessionCommand, create_session::create_session, Command};
use object::ObjectId;
use securechannel::SessionId;
use securechannel::{Challenge, Channel, CommandMessage, ResponseCode, ResponseMessage};
use serializers::deserialize;

/// Sessions with the YubiHSM2 are stateful and expire after 30 seconds. See:
/// <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
pub const SESSION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout fuzz factor: to avoid races/skew with the YubiHSM2's clock,
/// we consider sessions to be timed out slightly earlier than the actual
/// timeout. This should (hopefully) ensure we always time out first.
const TIMEOUT_SKEW_INTERVAL: Duration = Duration::from_secs(1);

/// Status message returned from healthy adapters
const CONNECTOR_STATUS_OK: &str = "OK";

/// Write consistent `debug!(...) lines for sessions
macro_rules! session_debug {
    ($session:expr, $msg:expr) => {
        debug!("yubihsm: session={} {}", $session.id().to_u8(), $msg);
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        debug!(concat!("yubihsm: session={} ", $fmt), $session.id().to_u8(), $($arg)+);
    };
}

/// Encrypted session with the `YubiHSM2`.
/// A session is needed to perform any commands.
///
/// Sessions are eneric over `Adapter` types in case a different one needs to
/// be swapped in, which is primarily useful for substituting the `MockHSM`.
///
/// Sessions are automatically closed on `Drop`, releasing `YubiHSM2` session
/// resources and wiping the ephemeral keys used to encrypt the session.
pub struct Session<A = HttpAdapter>
where
    A: Adapter,
{
    /// Encrypted channel to the HSM
    channel: Channel,

    /// Adapter to send messages through
    adapter: A,

    /// Instant when the last command with the YubiHSM2 was sent. Used for
    /// tracking session inactivity timeouts
    last_command_timestamp: Instant,

    /// Is the connection presumed to be healthy?
    active: bool,

    /// Cached `Credentials` for reconnecting lost sessions
    credentials: Option<Credentials>,
}

/// Credentials used to establish a YubiHSM2 session
struct Credentials {
    /// Key ID to authenticate with
    auth_key_id: ObjectId,

    /// Auth key to authenticate with
    auth_key: AuthKey,
}

// Special casing these for HttpAdapter is a bit of a hack in that default
// generics and static methods do not play well together, e.g.
//
// error[E0283]: type annotations required: cannot resolve `yubihsm::Adapter`
//
// So we special case these for HttpAdapter to make the API more ergonomic
impl Session<HttpAdapter> {
    /// Open a new session to the HSM, authenticating with the given `AuthKey`
    pub fn create(
        config: HttpConfig,
        auth_key_id: ObjectId,
        auth_key: AuthKey,
        reconnect: bool,
    ) -> Result<Self, SessionError> {
        let adapter_info = config.to_string();
        let adapter = HttpAdapter::open(config)?;
        let status = adapter.status()?;

        if status.message != CONNECTOR_STATUS_OK {
            session_fail!(
                CreateFailed,
                "bad status response from {}: {}",
                adapter_info,
                status.message
            );
        }

        Self::new(adapter, auth_key_id, auth_key, reconnect)
    }

    /// Open a new session to the HSM, authenticating with a given password.
    /// Uses the same password-based key derivation method as yubihsm-shell
    /// (PBKDF2 + static salt), which is not particularly strong, so use
    /// of a long, random password is recommended.
    #[cfg(feature = "passwords")]
    pub fn create_from_password(
        config: HttpConfig,
        auth_key_id: ObjectId,
        password: &[u8],
        reconnect: bool,
    ) -> Result<Self, SessionError> {
        Self::create(
            config,
            auth_key_id,
            AuthKey::derive_from_password(password),
            reconnect,
        )
    }
}

impl<A: Adapter> Session<A> {
    /// Create a new encrypted session using the given adapter, YubiHSM2 auth key ID, and
    /// authentication key
    pub fn new(
        adapter: A,
        auth_key_id: ObjectId,
        auth_key: AuthKey,
        reconnect: bool,
    ) -> Result<Self, SessionError> {
        debug!("yubihsm: creating new session");

        let credentials = Credentials {
            auth_key_id,
            auth_key,
        };

        let channel = Self::create_channel(&adapter, &credentials)?;

        let mut session = Self {
            channel,
            adapter,
            last_command_timestamp: Instant::now(),
            active: true,
            credentials: if reconnect { Some(credentials) } else { None },
        };

        session.authenticate(auth_key_id)?;
        Ok(session)
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> SessionId {
        self.channel.id()
    }

    /// Borrow the underlying adapter
    pub fn adapter(&mut self) -> &A {
        &self.adapter
    }

    /// Is the current session active?
    pub fn is_active(&self) -> bool {
        if !self.active || !self.adapter.status().is_ok() {
            return false;
        }

        let time_since_last_command = Instant::now().duration_since(self.last_command_timestamp);

        // Make sure the session hasn't timed out
        if time_since_last_command > (SESSION_INACTIVITY_TIMEOUT - TIMEOUT_SKEW_INTERVAL) {
            session_debug!(
                self,
                "session timed out after {} seconds (max {})",
                time_since_last_command.as_secs(),
                SESSION_INACTIVITY_TIMEOUT.as_secs()
            );

            return false;
        }

        true
    }

    /// Create a new encrypted session with the YubiHSM2
    fn create_channel(adapter: &A, credentials: &Credentials) -> Result<Channel, SessionError> {
        let host_challenge = Challenge::random();

        let (session_id, session_response) =
            create_session(adapter, credentials.auth_key_id, host_challenge)?;

        let channel = Channel::new(
            session_id,
            &credentials.auth_key,
            host_challenge,
            session_response.card_challenge,
        );

        if channel
            .card_cryptogram()
            .ct_eq(&session_response.card_cryptogram)
            .unwrap_u8() != 1
        {
            session_fail!(AuthFailed, "card cryptogram mismatch!");
        }

        Ok(channel)
    }

    /// Attempt to re-establish an encrypted connection with the YubiHSM2
    fn reconnect(&mut self) -> Result<(), SessionError> {
        let auth_key_id = match self.credentials {
            Some(ref credentials) => {
                // TODO: display adapter debug info?
                session_debug!(self, "attempting to reconnect");

                self.adapter.reconnect()?;
                self.channel = Self::create_channel(&self.adapter, credentials)?;
                credentials.auth_key_id
            }
            None => session_fail!(CreateFailed, "session reconnect is disabled"),
        };

        self.active = true;
        self.last_command_timestamp = Instant::now();
        self.authenticate(auth_key_id)?;

        Ok(())
    }

    /// Authenticate the current session with the `YubiHSM2`
    fn authenticate(&mut self, auth_key_id: ObjectId) -> Result<(), SessionError> {
        session_debug!(self, "authenticating session with key ID: {}", auth_key_id);

        let command = self.channel.authenticate_session()?;
        let response = self.send_command(command)?;

        if let Err(e) = self.channel.finish_authenticate_session(&response) {
            session_debug!(self, "error authenticating with key ID: {}", auth_key_id);
            self.active = false;
            return Err(e.into());
        }

        session_debug!(self, "session authenticated successfully");

        Ok(())
    }

    /// Send a command message to the YubiHSM2 and parse the response
    fn send_command(&mut self, cmd: CommandMessage) -> Result<ResponseMessage, SessionError> {
        // Attempt to automatically reconnect if the session is unhealthy
        if !self.is_active() {
            self.active = false;
            self.reconnect()?;
        }

        let cmd_type = cmd.command_type;
        let uuid = cmd.uuid;

        session_debug!(self, "uuid={} command={:?}", &uuid, cmd_type);

        let response_bytes = match self.adapter.send_command(uuid, cmd.into()) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Mark connection as unhealthy
                self.active = false;
                return Err(e.into());
            }
        };

        let response = ResponseMessage::parse(response_bytes)?;

        session_debug!(
            self,
            "uuid={} response={:?} length={}",
            &uuid,
            response.code,
            response.data.len()
        );

        self.last_command_timestamp = Instant::now();

        if response.is_err() {
            session_fail!(ResponseError, "HSM error: {:?}", response.code);
        }

        if response.command().unwrap() != cmd_type {
            self.active = false;

            session_fail!(
                ProtocolError,
                "command type mismatch: expected {:?}, got {:?}",
                cmd_type,
                response.command().unwrap()
            );
        }

        Ok(response)
    }

    /// Encrypt a command and send it to the card, then authenticate and
    /// decrypt the response
    pub(crate) fn send_encrypted_command<T: Command>(
        &mut self,
        command: T,
    ) -> Result<T::ResponseType, SessionError> {
        let encrypted_cmd = self.channel.encrypt_command(command.into())?;
        let uuid = encrypted_cmd.uuid;

        session_debug!(self, "uuid={} encrypted-cmd={:?}", uuid, T::COMMAND_TYPE);

        let encrypted_response = self.send_command(encrypted_cmd)?;
        let response = self.channel.decrypt_response(encrypted_response)?;

        session_debug!(
            self,
            "uuid={} decrypted-resp={:?} length={}",
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

            session_fail!(ResponseError, description);
        }

        if response.command().unwrap() != T::COMMAND_TYPE {
            session_fail!(
                ResponseError,
                "command type mismatch: expected {:?}, got {:?}",
                T::COMMAND_TYPE,
                response.command().unwrap()
            );
        }

        deserialize(response.data.as_ref()).map_err(|e| e.into())
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
        if !self.is_active() {
            return;
        }

        session_debug!(self, "closing dropped session");

        if let Err(e) = self.send_encrypted_command(CloseSessionCommand {}) {
            session_debug!(self, "error closing dropped session: {}", e);
        }
    }
}
