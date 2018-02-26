//! Secure Channel provided by the SCP03 protocol

use aesni::Aes128;
use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::clear::Clear;
use cmac::Cmac;
use cmac::crypto_mac::Mac as CryptoMac;
use failure::Error;

use super::kdf;
use super::{Challenge, Command, CommandType, Context, Cryptogram, Mac, Response,
            SecureChannelError, StaticKeys, CRYPTOGRAM_SIZE, KEY_SIZE, MAC_SIZE};

/// Session/Channel IDs
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Id(u8);

impl Id {
    /// Create a new session ID from a byte value
    pub fn new(id: u8) -> Result<Self, Error> {
        if id > MAX_ID.0 {
            fail!(
                SecureChannelError::ProtocolError,
                "session ID exceeds the maximum allowed: {} (max {})",
                id,
                MAX_ID.0
            );
        }

        Ok(Id(id))
    }

    /// Obtain the next session ID
    pub fn succ(&self) -> Result<Self, Error> {
        Self::new(self.0 + 1)
    }

    /// Obtain session ID as a u8
    pub fn to_u8(&self) -> u8 {
        self.0
    }
}

/// Maximum session identifier
pub const MAX_ID: Id = Id(16);

/// Maximum number of messages allowed in a single session: 2^20.
///
/// This is a conservative number chosen due to the small MAC size used by
/// the SCP03 protocol: 8-bytes. This small tag has an even smaller birthday
/// bound on collisions, so to avoid these we force generation of fresh
/// session keys after the following number of messages have been sent.
pub const MAX_COMMANDS_PER_SESSION: usize = 0x10_0000;

/// Current Security Level: protocol state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityLevel {
    /// 'NO_SECURITY_LEVEL' i.e. session is terminated or not fully initialized
    NoSecurityLevel,

    /// 'AUTHENTICATED' i.e. the EXTERNAL_AUTHENTICATE command has completed
    Authenticated,
}

/// SCP03 Secure Channel
pub(crate) struct Channel {
    // ID of this channel (a.k.a. session ID)
    id: Id,

    // Counter of total commands performed in this session
    counter: usize,

    // External authentication state
    security_level: SecurityLevel,

    // Context (card + host challenges)
    context: Context,

    // Session encryption key (S-ENC)
    enc_key: [u8; KEY_SIZE],

    // Session Command MAC key (S-MAC)
    mac_key: [u8; KEY_SIZE],

    // Session Respose MAC key (S-RMAC)
    rmac_key: [u8; KEY_SIZE],

    // Chaining value to be included when computing MACs
    mac_chaining_value: [u8; MAC_SIZE * 2],
}

impl Channel {
    /// Create a new channel with the given ID, static keys, and host/card challenges
    pub fn new(
        id: Id,
        static_keys: &StaticKeys,
        host_challenge: &Challenge,
        card_challenge: &Challenge,
    ) -> Self {
        let context = Context::from_challenges(host_challenge, card_challenge);
        let enc_key = derive_key(&static_keys.enc_key, 0b100, &context);
        let mac_key = derive_key(&static_keys.mac_key, 0b110, &context);
        let rmac_key = derive_key(&static_keys.mac_key, 0b111, &context);
        let mac_chaining_value = [0u8; MAC_SIZE * 2];

        Self {
            id,
            counter: 0,
            security_level: SecurityLevel::NoSecurityLevel,
            context,
            enc_key,
            mac_key,
            rmac_key,
            mac_chaining_value,
        }
    }

    /// Calculate the card's cryptogram for this session
    pub fn card_cryptogram(&self) -> Cryptogram {
        let mut result_bytes = [0u8; CRYPTOGRAM_SIZE];
        kdf::derive(&self.mac_key, 0, &self.context, &mut result_bytes);

        let result = Cryptogram::from_slice(&result_bytes);
        result_bytes.clear();

        result
    }

    /// Calculate the host's cryptogram for this session
    pub fn host_cryptogram(&self) -> Cryptogram {
        let mut result_bytes = [0u8; CRYPTOGRAM_SIZE];
        kdf::derive(&self.mac_key, 1, &self.context, &mut result_bytes);

        let result = Cryptogram::from_slice(&result_bytes);
        result_bytes.clear();

        result
    }

    /// Compute a command message with a MAC value for this session
    pub fn command_with_mac(
        &mut self,
        command_type: CommandType,
        command_data: &[u8],
    ) -> Result<Command, Error> {
        if self.counter >= MAX_COMMANDS_PER_SESSION {
            fail!(
                SecureChannelError::SessionLimitReached,
                "max of {} commands per session exceeded",
                MAX_COMMANDS_PER_SESSION
            );
        }

        let mut mac = Cmac::<Aes128>::new_varkey(&self.mac_key[..]).unwrap();
        mac.input(&self.mac_chaining_value);
        mac.input(&[command_type as u8]);

        let mut length = [0u8; 2];
        BigEndian::write_u16(&mut length, (1 + command_data.len() + MAC_SIZE) as u16);
        mac.input(&length);
        mac.input(&[self.id.to_u8()]);
        mac.input(command_data);

        let tag = mac.result().code();
        self.mac_chaining_value.copy_from_slice(tag.as_slice());
        self.counter += 1;

        Ok(Command::new_with_mac(
            command_type,
            self.id,
            command_data,
            Mac::from_slice(&tag.as_slice()[..MAC_SIZE]),
        ))
    }

    /// Compute a message for authenticating the host to the card
    pub fn authenticate_session(&mut self) -> Result<Command, Error> {
        assert_eq!(self.security_level, SecurityLevel::NoSecurityLevel);
        assert_eq!(self.mac_chaining_value, [0u8; MAC_SIZE * 2]);

        let host_cryptogram = self.host_cryptogram();
        self.command_with_mac(CommandType::AuthSession, host_cryptogram.as_slice())
    }

    /// Handle the authenticate session response from the card
    pub fn finish_authenticate_session(&mut self, response: &Response) -> Result<(), Error> {
        // The EXTERNAL_AUTHENTICATE command does not send an R-MAC value
        if !response.body().is_empty() {
            fail!(
                SecureChannelError::ProtocolError,
                "expected empty response data (got {}-bytes)",
                response.body().len(),
            );
        }

        self.security_level = SecurityLevel::Authenticated;
        Ok(())
    }

    /// Verify a host authentication message (for simulating a connector/card)
    #[cfg(feature = "mockhsm")]
    pub fn verify_authenticate_session(&mut self, command: &Command) -> Result<(), Error> {
        assert_eq!(self.security_level, SecurityLevel::NoSecurityLevel);
        assert_eq!(self.mac_chaining_value, [0u8; MAC_SIZE * 2]);

        if command.data.len() != CRYPTOGRAM_SIZE {
            fail!(
                SecureChannelError::ProtocolError,
                "expected {}-byte command data (got {})",
                CRYPTOGRAM_SIZE,
                command.data.len()
            );
        }

        let expected_host_cryptogram = self.host_cryptogram();
        let actual_host_cryptogram = Cryptogram::from_slice(&command.data);

        if expected_host_cryptogram != actual_host_cryptogram {
            fail!(
                SecureChannelError::VerifyFailed,
                "host cryptogram mismatch!"
            );
        }

        self.verify_command_mac(command)?;
        self.security_level = SecurityLevel::Authenticated;

        Ok(())
    }

    /// Verify a Command MAC (C-MAC) value, updating the internal session state
    #[cfg(feature = "mockhsm")]
    pub fn verify_command_mac(&mut self, command: &Command) -> Result<(), Error> {
        let mut mac = Cmac::<Aes128>::new_varkey(&self.mac_key[..]).unwrap();
        mac.input(&self.mac_chaining_value);
        mac.input(&[command.command_type as u8]);

        let mut length = [0u8; 2];
        BigEndian::write_u16(&mut length, command.len() as u16);
        mac.input(&length);
        mac.input(&[command.session_id.unwrap().to_u8()]);
        mac.input(&command.data);

        command
            .mac
            .as_ref()
            .expect("missing MAC tag!")
            .verify(mac.result(), &mut self.mac_chaining_value)?;

        Ok(())
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.enc_key.clear();
        self.mac_key.clear();
        self.rmac_key.clear();
    }
}

/// Derive a key using the SCP03 KDF
fn derive_key(
    parent_key: &[u8; KEY_SIZE],
    derivation_constant: u8,
    context: &Context,
) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    kdf::derive(parent_key, derivation_constant, context, &mut key);
    key
}
