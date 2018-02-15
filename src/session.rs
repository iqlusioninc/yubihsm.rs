//! YubiHSM2 sessions: primary API for performing HSM operations
//!
//! See <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>

use byteorder::{BigEndian, WriteBytesExt};
use command::CommandType;
use connector::Connector;
use failure::Error;
use scp03::{Challenge, Context, Cryptogram, IdentityKeys, SessionKeys, CHALLENGE_SIZE};
use super::KeyID;

/// Maximum session identifier
const MAX_SESSION_ID: u8 = 16;

/// Encrypted session with the YubiHSM2
// TODO: don't allow dead code
#[allow(dead_code)]
pub struct Session<'a> {
    connector: &'a Connector,
    id: SessionID,
    keys: SessionKeys,
}

/// Session-related errors
#[derive(Debug, Fail)]
pub enum SessionError {
    /// Couldn't create session
    #[fail(display = "couldn't create session: {}", description)]
    CreateFailed {
        /// Description of why we couldn't create the session
        description: String,
    },

    /// Couldn't authenticate session
    #[fail(display = "authentication failed: {}", description)]
    AuthenticationFailed {
        /// Details about the authentication failure
        description: String,
    },
}

impl<'a> Session<'a> {
    /// Create a new encrypted session using the given auth key and password
    pub fn new(
        connector: &'a Connector,
        host_challenge: &Challenge,
        auth_key_id: KeyID,
        static_keys: IdentityKeys,
    ) -> Result<Self, Error> {
        let mut payload = Vec::with_capacity(10);
        payload.write_u16::<BigEndian>(auth_key_id)?;
        payload.extend_from_slice(host_challenge.as_slice());

        let response = connector.command(CommandType::CreateSession, payload)?;

        if response.is_err() {
            Err(SessionError::CreateFailed {
                description: format!("HSM error: {:?}", response.code()),
            })?;
        }

        if response.command().unwrap() != CommandType::CreateSession {
            Err(SessionError::CreateFailed {
                description: format!(
                    "invalid response length {} (expected {})",
                    response.body().len(),
                    1 + CHALLENGE_SIZE * 2
                ),
            })?;
        }

        let response_body = response.body();
        if response_body.len() != 1 + CHALLENGE_SIZE * 2 {
            Err(SessionError::CreateFailed {
                description: format!("command type mismatch: {:?}", response.command().unwrap()),
            })?;
        }

        let session_id = SessionID::new(response_body[0])?;
        let card_challenge = Challenge::from_slice(&response_body[1..9]);
        let context = Context::from_challenges(&host_challenge, &card_challenge);
        let session_keys = SessionKeys::derive(&static_keys, &context);
        let expected_card_cryptogram = session_keys.card_cryptogram(&context);
        let actual_card_cryptogram = Cryptogram::from_slice(&response_body[9..17]);

        if expected_card_cryptogram != actual_card_cryptogram {
            Err(SessionError::AuthenticationFailed {
                description: "card cryptogram verification failed!".to_owned(),
            })?;
        }

        Ok(Self {
            connector,
            id: session_id,
            keys: session_keys,
        })
    }

    /// Get the current session ID
    pub fn id(&self) -> SessionID {
        self.id
    }
}

/// Session IDs
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SessionID(pub u8);

impl SessionID {
    fn new(id: u8) -> Result<Self, Error> {
        if id > MAX_SESSION_ID {
            bail!("session ID exceeds the maximum allowed")
        }

        Ok(SessionID(id))
    }
}
