//! Encrypted connection to the HSM through a particular adapter

use subtle::ConstantTimeEq;

use super::{SessionError, SessionErrorKind::*};
use adapters::Adapter;
use commands::create_session::create_session;
use credentials::Credentials;
use securechannel::{Challenge, CommandMessage, ResponseMessage, SecureChannel, SessionId};

/// Encrypted connection to the HSM made through a particular adapter.
/// This type handles opening/closing adapters and creating encrypted
/// (SCP03) channels.
pub(crate) struct Connection<A: Adapter> {
    /// Adapter which communicates with the HSM (HTTP or USB)
    pub(crate) adapter: Option<A>,

    /// Encrypted (SCP03) channel to the HSM
    pub(crate) channel: Option<SecureChannel>,

    /// Configuration for the adapter
    pub(crate) config: A::Config,
}

impl<A: Adapter> Connection<A> {
    /// Create a new connection object, deferring connecting until the
    /// `connect` function is called.
    pub fn new(config: A::Config) -> Self {
        Connection {
            adapter: None,
            channel: None,
            config,
        }
    }

    /// Connect to the HSM using the given credentials
    pub fn open(&mut self, credentials: &Credentials) -> Result<(), SessionError> {
        self.channel = {
            let adapter = self.open_adapter()?;
            let host_challenge = Challenge::random();

            let (session_id, session_response) =
                create_session(adapter, credentials.auth_key_id, host_challenge)?;

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
                fail!(AuthFailed, "card cryptogram mismatch!");
            }

            Some(channel)
        };

        self.authenticate_channel(credentials)?;
        Ok(())
    }

    /// Do we have an active connection to the HSM?
    pub fn is_open(&self) -> bool {
        self.adapter.is_some() && self.channel.is_some()
    }

    /// Get the current session ID (if we have an open session)
    #[inline]
    pub fn id(&self) -> Option<SessionId> {
        self.channel.as_ref().map(|c| c.id())
    }

    /// Get the currently open `SecureChannel` for this connection
    pub fn secure_channel(&mut self) -> Result<&mut SecureChannel, SessionError> {
        self.channel
            .as_mut()
            .ok_or_else(|| err!(CreateFailed, "couldn't open secure channel"))
    }

    /// Close the currently open `SecureChannel` for this connection (if any),
    /// also checking the adapter's health and potentially closing it as well
    /// if it's unhealthy.
    pub fn close_secure_channel(&mut self) {
        self.channel = None;

        // Check that the `Adapter` is still healthy, and if it isn't, drop it
        // in addition to the `SecureChannel`.
        //
        // This check is potentially expensive (i.e. HTTP request) so we avoid
        // doing it unless we presume the underlying connection may be
        // unhealthy.
        let adapter_is_open = self.adapter.as_ref().map(|a| a.is_open()).unwrap_or(false);

        if !adapter_is_open {
            self.adapter = None;
        }
    }

    /// Send a command message to the HSM and parse the response
    pub fn send_message(&mut self, cmd: CommandMessage) -> Result<ResponseMessage, SessionError> {
        let session_id = self.secure_channel()?.id().to_u8();
        let cmd_type = cmd.command_type;
        let uuid = cmd.uuid;

        debug!(
            "(session: {}) uuid={} command={:?}",
            session_id, &uuid, cmd_type
        );

        let response = match self.open_adapter()?.send_message(uuid, cmd.into()) {
            Ok(response_bytes) => ResponseMessage::parse(response_bytes)?,
            Err(e) => {
                self.close_secure_channel();
                return Err(e.into());
            }
        };

        debug!(
            "(session: {}) uuid={} response={:?} length={}",
            session_id,
            &uuid,
            response.code,
            response.data.len()
        );

        if response.is_err() {
            error!(
                "(session: {}) uuid={} HSM error: {:?}",
                session_id,
                &uuid,
                response.data.len()
            );

            fail!(
                ResponseError,
                "(session: {}) HSM error: {:?}",
                session_id,
                response.code
            );
        }

        if response.command().unwrap() != cmd_type {
            self.close_secure_channel();

            fail!(
                ProtocolError,
                "(session: {}) command type mismatch: expected {:?}, got {:?}",
                session_id,
                cmd_type,
                response.command().unwrap()
            );
        }

        Ok(response)
    }

    /// Open the underlying adapter, either using our existing connection or
    /// creating a new one
    pub fn open_adapter(&mut self) -> Result<&A, SessionError> {
        if let Some(ref adapter) = self.adapter {
            return Ok(adapter);
        }

        let adapter = A::open(&self.config)?;

        // Ensure the new connection is healthy
        if !adapter.is_open() {
            fail!(
                CreateFailed,
                "adapter unhealthy. check debug log for more info."
            )
        }

        self.adapter = Some(adapter);
        Ok(self.adapter.as_ref().unwrap())
    }

    /// Authenticate the current session with the HSM
    fn authenticate_channel(&mut self, credentials: &Credentials) -> Result<(), SessionError> {
        let session_id = self.secure_channel()?.id().to_u8();

        debug!(
            "(session: {}) authenticating with key: {}",
            session_id, credentials.auth_key_id
        );

        let command = self.secure_channel()?.authenticate_session()?;
        let response = self.send_message(command)?;

        if let Err(e) = self
            .secure_channel()?
            .finish_authenticate_session(&response)
        {
            error!(
                "(session: {}) error authenticating with key: {} ({})",
                session_id, credentials.auth_key_id, e
            );
            self.close_secure_channel();
            return Err(e.into());
        }

        debug!("(session: {}) authenticated successfully", session_id);

        Ok(())
    }
}
