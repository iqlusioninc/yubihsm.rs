//! Implementation of the GlobalPlatform Secure Channel Protocol '03' (SCP03)
//!
//! See GPC_SPE_014: GlobalPlatform Card Technology Secure Channel Protocol '03' at:
//! <https://www.globalplatform.org/specificationscard.asp>
//!
//! SCP03 provides an encrypted channel using symmetric encryption alone.
//! AES-128-CBC is used for encryption, and AES-128-CMAC for authentication.
//!
//! While SCP03 is a multipurpose protocol, this implementation has been
//! written with the specific intention of communicating with Yubico's
//! YubiHSM 2 devices and therefore omits certain features (e.g. additional
//! key sizes besides 128-bit) which are not relevant to the YubiHSM 2 use case.
//!
//! It also follows the APDU format as described in Yubico's YubiHSM 2
//! documentation as opposed to the one specified in GPC_SPE_014.
//!
//! For more information on the YubiHSM 2 command format, see:
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

mod challenge;
mod context;
mod cryptogram;
mod kdf;
mod mac;

pub use self::{challenge::Challenge, context::Context};
pub(crate) use self::{
    challenge::CHALLENGE_SIZE,
    cryptogram::{Cryptogram, CRYPTOGRAM_SIZE},
    mac::Mac,
};
use super::commands::{CreateSessionCommand, CreateSessionResponse};
use crate::{
    authentication::{self, Credentials},
    command,
    connector::Connector,
    device, object, response,
    serialization::deserialize,
    session::{self, ErrorKind},
};
use aes::{
    cipher::{
        block_padding::Iso7816, consts::U16, generic_array::GenericArray, BlockDecryptMut,
        BlockEncrypt, BlockEncryptMut, InnerIvInit, KeyInit,
    },
    Aes128,
};
use cmac::{digest::Mac as _, Cmac};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// AES key size in bytes. SCP03 theoretically supports other key sizes, but
/// the YubiHSM 2 does not. Since this crate is somewhat specialized to the `YubiHSM 2` (at least for now)
/// we hardcode to 128-bit for simplicity.
pub(crate) const KEY_SIZE: usize = 16;

/// Maximum number of messages allowed in a single session: 2^20.
///
/// This is a conservative number chosen due to the small MAC size used by
/// the SCP03 protocol: 8-bytes. This small tag has an even smaller birthday
/// bound on collisions, so to avoid these we force generation of fresh
/// session keys after the following number of messages have been sent.
pub const MAX_COMMANDS_PER_SESSION: u32 = 0x10_0000;

/// Size of an AES block (128-bits)
const AES_BLOCK_SIZE: usize = 16;

/// SCP03 uses AES-128 encryption in CBC mode with ISO 7816 padding
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// SCP03 AES Session Keys
#[derive(Serialize, Deserialize)]
pub struct SessionKeys {
    /// Session encryption key (S-ENC)
    pub enc_key: [u8; KEY_SIZE],

    /// Session Command MAC key (S-MAC)
    pub mac_key: [u8; KEY_SIZE],

    /// Session Respose MAC key (S-RMAC)
    pub rmac_key: [u8; KEY_SIZE],
}

impl Zeroize for SessionKeys {
    fn zeroize(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
        self.rmac_key.zeroize();
    }
}

#[cfg(feature = "yubihsm-auth")]
impl From<yubikey::hsmauth::SessionKeys> for SessionKeys {
    fn from(keys: yubikey::hsmauth::SessionKeys) -> Self {
        let enc_key = *keys.enc_key;
        let mac_key = *keys.mac_key;
        let rmac_key = *keys.rmac_key;

        Self {
            enc_key,
            mac_key,
            rmac_key,
        }
    }
}

/// SCP03 Secure Channel
pub(crate) struct SecureChannel {
    /// ID of this channel (a.k.a. session ID)
    id: session::Id,

    /// Number of messages sent over this channel
    counter: u32,

    /// External authentication state
    // TODO(tarcieri): use session types to model the protocol state machine?
    security_level: SecurityLevel,

    /// Context (card + host challenges)
    context: Context,

    /// Session keys
    session_keys: SessionKeys,

    /// Chaining value to be included when computing MACs
    mac_chaining_value: [u8; Mac::BYTE_SIZE * 2],
}

impl SecureChannel {
    /// Open a SecureChannel, performing challenge/response authentication and
    /// establishing a session key
    pub(crate) fn open(
        connector: &Connector,
        credentials: &Credentials,
    ) -> Result<Self, session::Error> {
        let host_challenge = Challenge::new();

        let (id, session_response) =
            Self::create(connector, credentials.authentication_key_id, host_challenge)?;

        // Derive session keys from the combination of host and card challenges.
        // If either of them are incorrect (indicating a key mismatch) it will
        // result in a cryptogram verification failure.
        let channel = Self::new(
            id,
            &credentials.authentication_key,
            host_challenge,
            session_response.card_challenge,
        );

        if channel
            .card_cryptogram()
            .ct_eq(&session_response.card_cryptogram)
            .unwrap_u8()
            != 1
        {
            fail!(
                ErrorKind::AuthenticationError,
                "(session: {}) invalid credentials for authentication key #{} (cryptogram mismatch)",
                channel.id().to_u8(),
                credentials.authentication_key_id,
            );
        }

        Ok(channel)
    }

    /// Create a new channel with the given ID, auth key, and host/card challenges
    pub(crate) fn new(
        id: session::Id,
        authentication_key: &authentication::Key,
        host_challenge: Challenge,
        card_challenge: Challenge,
    ) -> Self {
        let context = Context::from_challenges(host_challenge, card_challenge);
        let enc_key = derive_key(authentication_key.enc_key(), 0b100, &context);
        let mac_key = derive_key(authentication_key.mac_key(), 0b110, &context);
        let rmac_key = derive_key(authentication_key.mac_key(), 0b111, &context);

        let session_keys = SessionKeys {
            enc_key,
            mac_key,
            rmac_key,
        };
        Self::with_session_keys(id, context, session_keys)
    }

    pub(crate) fn with_session_keys(
        id: session::Id,
        context: Context,
        session_keys: SessionKeys,
    ) -> Self {
        let mac_chaining_value = [0u8; Mac::BYTE_SIZE * 2];

        Self {
            id,
            counter: 0,
            security_level: SecurityLevel::None,
            context,
            session_keys,
            mac_chaining_value,
        }
    }

    /// Open a SecureChannel with the HSM. This will not complete authentication.
    ///
    /// This will return the session id as well as the card challenge.
    pub(crate) fn create(
        connector: &Connector,
        authentication_key_id: object::Id,
        host_challenge: Challenge,
    ) -> Result<(session::Id, CreateSessionResponse), session::Error> {
        let command_message = command::Message::from(&CreateSessionCommand {
            authentication_key_id, //: credentials.authentication_key_id,
            host_challenge,
        });

        let uuid = command_message.uuid;
        let response_body = connector.send_message(uuid, command_message.into())?;
        let response_message = response::Message::parse(response_body)?;

        if response_message.is_err() {
            match device::ErrorKind::from_response_message(&response_message) {
                Some(device::ErrorKind::ObjectNotFound) => fail!(
                    ErrorKind::AuthenticationError,
                    "auth key not found: 0x{:04x}",
                    authentication_key_id
                ),
                Some(kind) => return Err(kind.into()),
                None => fail!(
                    ErrorKind::ResponseError,
                    "HSM error: {:?}",
                    response_message.code
                ),
            }
        }

        if response_message.command().unwrap() != command::Code::CreateSession {
            fail!(
                ErrorKind::ProtocolError,
                "command type mismatch: expected {:?}, got {:?}",
                command::Code::CreateSession,
                response_message.command().unwrap()
            );
        }

        let id = response_message
            .session_id
            .ok_or_else(|| format_err!(ErrorKind::CreateFailed, "no session ID in response"))?;

        let session_response: CreateSessionResponse = deserialize(response_message.data.as_ref())?;

        Ok((id, session_response))
    }

    /// Get the channel (i.e. session) ID
    pub fn id(&self) -> session::Id {
        self.id
    }

    /// Calculate the card's cryptogram for this session
    pub fn card_cryptogram(&self) -> Cryptogram {
        let mut result_bytes = Zeroizing::new([0u8; CRYPTOGRAM_SIZE]);
        kdf::derive(
            &self.session_keys.mac_key,
            0,
            &self.context,
            result_bytes.as_mut(),
        );
        Cryptogram::from_slice(result_bytes.as_ref())
    }

    /// Calculate the host's cryptogram for this session
    pub fn host_cryptogram(&self) -> Cryptogram {
        let mut result_bytes = Zeroizing::new([0u8; CRYPTOGRAM_SIZE]);
        kdf::derive(
            &self.session_keys.mac_key,
            1,
            &self.context,
            result_bytes.as_mut(),
        );
        Cryptogram::from_slice(result_bytes.as_ref())
    }

    /// Compute a command message with a MAC value for this session
    pub fn command_with_mac(
        &mut self,
        command_type: command::Code,
        command_data: &[u8],
    ) -> Result<command::Message, session::Error> {
        if self.counter >= MAX_COMMANDS_PER_SESSION {
            self.terminate();
            fail!(
                ErrorKind::CommandLimitExceeded,
                "session limit of {} messages exceeded",
                MAX_COMMANDS_PER_SESSION
            );
        }

        let mut mac =
            <Cmac<Aes128> as KeyInit>::new_from_slice(self.session_keys.mac_key.as_ref()).unwrap();
        mac.update(&self.mac_chaining_value);
        mac.update(&[command_type.to_u8()]);

        let length = (1 + command_data.len() + Mac::BYTE_SIZE) as u16;
        mac.update(&length.to_be_bytes());
        mac.update(&[self.id.to_u8()]);
        mac.update(command_data);

        let tag = mac.finalize().into_bytes();
        self.mac_chaining_value.copy_from_slice(tag.as_slice());

        command::Message::new_with_mac(command_type, self.id, command_data, &tag)
    }

    /// Compute a message for authenticating the host to the card
    pub fn authenticate_session(&mut self) -> Result<command::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::None);
        assert_eq!(self.mac_chaining_value, [0u8; Mac::BYTE_SIZE * 2]);

        let host_cryptogram = self.host_cryptogram();
        self.command_with_mac(
            command::Code::AuthenticateSession,
            host_cryptogram.as_slice(),
        )
    }

    /// Handle the authenticate session response from the card
    pub fn finish_authenticate_session(
        &mut self,
        response: &response::Message,
    ) -> Result<(), session::Error> {
        // The EXTERNAL_AUTHENTICATE command does not send an R-MAC value
        if !response.data.is_empty() {
            self.terminate();
            fail!(
                ErrorKind::ProtocolError,
                "expected empty response data (got {}-bytes)",
                response.data.len(),
            );
        }

        self.security_level = SecurityLevel::Authenticated;

        // "The encryption counter’s start value shall be set to 1 for the
        // first command following a successful EXTERNAL AUTHENTICATE
        // command." -- GPC_SPE_014 section 6.2.6
        self.counter = 1;

        Ok(())
    }

    /// Encrypt a command to be sent to the card
    pub fn encrypt_command(
        &mut self,
        command: command::Message,
    ) -> Result<command::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);

        let mut message = command.serialize();
        let pos = message.len();

        // Provide space at the end of the vec for the padding
        message.extend_from_slice(&[0u8; AES_BLOCK_SIZE]);

        let cipher = Aes128::new_from_slice(&self.session_keys.enc_key).unwrap();
        let icv = compute_icv(&cipher, self.counter);
        let cbc_encryptor = Aes128CbcEnc::inner_iv_init(cipher, &icv);
        let ciphertext = cbc_encryptor
            .encrypt_padded_mut::<Iso7816>(&mut message, pos)
            .unwrap();

        self.command_with_mac(command::Code::SessionMessage, ciphertext)
    }

    /// Verify and decrypt a response from the card
    pub fn decrypt_response(
        &mut self,
        encrypted_response: response::Message,
    ) -> Result<response::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);

        let cipher = Aes128::new_from_slice(&self.session_keys.enc_key).unwrap();
        let icv = compute_icv(&cipher, self.counter);

        self.verify_response_mac(&encrypted_response)?;

        let cbc_decryptor = Aes128CbcDec::inner_iv_init(cipher, &icv);

        let mut response_message = encrypted_response.data;
        let response_len = cbc_decryptor
            .decrypt_padded_mut::<Iso7816>(&mut response_message)
            .map_err(|e| {
                self.terminate();
                format_err!(
                    ErrorKind::ProtocolError,
                    "error decrypting response: {:?}",
                    e
                )
            })?
            .len();

        response_message.truncate(response_len);
        let mut decrypted_response = response::Message::parse(response_message.into())?;
        decrypted_response.session_id = encrypted_response.session_id;

        Ok(decrypted_response)
    }

    /// Ensure message authenticity by verifying the response MAC (R-MAC) sent from the card
    pub fn verify_response_mac(
        &mut self,
        response: &response::Message,
    ) -> Result<(), session::Error> {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);

        let session_id = response.session_id.ok_or_else(|| {
            self.terminate();
            format_err!(ErrorKind::ProtocolError, "no session ID in response")
        })?;

        if self.id != session_id {
            self.terminate();
            fail!(
                ErrorKind::MismatchError,
                "message has session ID {} (expected {})",
                session_id.to_u8(),
                self.id.to_u8(),
            );
        }

        let mut mac =
            <Cmac<Aes128> as KeyInit>::new_from_slice(self.session_keys.rmac_key.as_ref()).unwrap();
        mac.update(&self.mac_chaining_value);
        mac.update(&[response.code.to_u8()]);

        let length = response.len() as u16;
        mac.update(&length.to_be_bytes());
        mac.update(&[session_id.to_u8()]);
        mac.update(&response.data);

        if response
            .mac
            .as_ref()
            .expect("missing R-MAC tag!")
            .verify(&mac.finalize().into_bytes())
            .is_err()
        {
            self.terminate();
            fail!(ErrorKind::VerifyFailed, "R-MAC mismatch!");
        }

        self.increment_counter();
        Ok(())
    }

    /// Verify a host authentication message (for simulating a connector/card)
    #[cfg(feature = "mockhsm")]
    pub fn verify_authenticate_session(
        &mut self,
        command: &command::Message,
    ) -> Result<response::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::None);
        assert_eq!(self.mac_chaining_value, [0u8; Mac::BYTE_SIZE * 2]);

        if command.data.len() != CRYPTOGRAM_SIZE {
            self.terminate();
            fail!(
                ErrorKind::ProtocolError,
                "expected {}-byte command data (got {})",
                CRYPTOGRAM_SIZE,
                command.data.len()
            );
        }

        let expected_host_cryptogram = self.host_cryptogram();
        let actual_host_cryptogram = Cryptogram::from_slice(&command.data);

        if expected_host_cryptogram
            .ct_eq(&actual_host_cryptogram)
            .unwrap_u8()
            != 1
        {
            self.terminate();
            fail!(ErrorKind::VerifyFailed, "host cryptogram mismatch!");
        }

        self.verify_command_mac(command)?;
        self.security_level = SecurityLevel::Authenticated;

        // "The encryption counter’s start value shall be set to 1 for the
        // first command following a successful EXTERNAL AUTHENTICATE
        // command." -- GPC_SPE_014 section 6.2.6
        self.counter = 1;

        Ok(response::Message::success(
            command::Code::AuthenticateSession,
            vec![],
        ))
    }

    /// Verify and decrypt a command from the host
    #[cfg(feature = "mockhsm")]
    pub fn decrypt_command(
        &mut self,
        encrypted_command: command::Message,
    ) -> Result<command::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);

        let cipher = Aes128::new_from_slice(&self.session_keys.enc_key).unwrap();
        let icv = compute_icv(&cipher, self.counter);

        self.verify_command_mac(&encrypted_command)?;

        let cipher = Aes128::new_from_slice(&self.session_keys.enc_key).unwrap();
        let cbc_decryptor = Aes128CbcDec::inner_iv_init(cipher, &icv);

        let mut command_data = encrypted_command.data;
        let command_len = cbc_decryptor
            .decrypt_padded_mut::<Iso7816>(&mut command_data)
            .map_err(|e| {
                self.terminate();
                format_err!(
                    ErrorKind::ProtocolError,
                    "error decrypting command: {:?}",
                    e
                )
            })?
            .len();

        command_data.truncate(command_len);
        let mut decrypted_command = command::Message::parse(command_data)?;
        decrypted_command.session_id = encrypted_command.session_id;

        Ok(decrypted_command)
    }

    /// Verify a Command MAC (C-MAC) value, updating the internal session state
    #[cfg(feature = "mockhsm")]
    pub fn verify_command_mac(&mut self, command: &command::Message) -> Result<(), session::Error> {
        assert_eq!(
            command.session_id.unwrap(),
            self.id,
            "session ID mismatch: {:?}",
            command.session_id
        );

        let mut mac =
            <Cmac<Aes128> as KeyInit>::new_from_slice(self.session_keys.mac_key.as_ref()).unwrap();
        mac.update(&self.mac_chaining_value);
        mac.update(&[command.command_type.to_u8()]);

        let length = command.len() as u16;
        mac.update(&length.to_be_bytes());
        mac.update(&[command.session_id.unwrap().to_u8()]);
        mac.update(&command.data);

        let tag = mac.finalize().into_bytes();

        if command
            .mac
            .as_ref()
            .expect("missing C-MAC tag!")
            .verify(&tag)
            .is_err()
        {
            self.terminate();
            fail!(ErrorKind::VerifyFailed, "C-MAC mismatch!");
        }

        self.mac_chaining_value.copy_from_slice(tag.as_slice());
        Ok(())
    }

    /// Encrypt a response to be sent back to the host
    #[cfg(feature = "mockhsm")]
    pub fn encrypt_response(
        &mut self,
        response: response::Message,
    ) -> Result<response::Message, session::Error> {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);

        let mut message: Vec<u8> = response.into();
        let pos = message.len();

        // Provide space at the end of the vec for the padding
        message.extend_from_slice(&[0u8; AES_BLOCK_SIZE]);

        let cipher = Aes128::new_from_slice(&self.session_keys.enc_key).unwrap();
        let icv = compute_icv(&cipher, self.counter);
        let cbc_encryptor = Aes128CbcEnc::inner_iv_init(cipher, &icv);

        let ct_len = cbc_encryptor
            .encrypt_padded_mut::<Iso7816>(&mut message, pos)
            .unwrap()
            .len();
        message.truncate(ct_len);

        self.response_with_mac(
            response::Code::Success(command::Code::SessionMessage),
            message,
        )
    }

    /// Compute the MAC for a response message
    #[cfg(feature = "mockhsm")]
    pub fn response_with_mac<T>(
        &mut self,
        code: response::Code,
        response_data: T,
    ) -> Result<response::Message, session::Error>
    where
        T: Into<Vec<u8>>,
    {
        assert_eq!(self.security_level, SecurityLevel::Authenticated);
        let body = response_data.into();

        let mut mac =
            <Cmac<Aes128> as KeyInit>::new_from_slice(self.session_keys.rmac_key.as_ref()).unwrap();
        mac.update(&self.mac_chaining_value);
        mac.update(&[code.to_u8()]);

        let length = (1 + body.len() + Mac::BYTE_SIZE) as u16;
        mac.update(&length.to_be_bytes());
        mac.update(&[self.id.to_u8()]);
        mac.update(&body);

        self.increment_counter();

        Ok(response::Message::new_with_mac(
            code,
            self.id,
            body,
            &mac.finalize().into_bytes(),
        ))
    }

    /// Get the current value of the internal message counter
    pub(super) fn counter(&self) -> usize {
        self.counter as usize
    }

    /// Increment the internal message counter
    fn increment_counter(&mut self) {
        self.counter = self.counter.checked_add(1).unwrap_or_else(|| {
            // We should always hit MAX_COMMANDS_PER_SESSION before this
            // happens unless there is a bug.
            panic!("session counter overflowed!");
        });
    }

    /// Terminate the session
    fn terminate(&mut self) {
        self.security_level = SecurityLevel::Terminated;
        self.session_keys.zeroize();
    }
}

impl Drop for SecureChannel {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Current Security Level: protocol state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityLevel {
    /// 'NO_SECURITY_LEVEL' i.e. session is terminated or not fully initialized
    None,

    /// 'AUTHENTICATED' i.e. the EXTERNAL_AUTHENTICATE command has completed
    Authenticated,

    /// Terminated: either explicitly closed or due to protocol error
    Terminated,
}

/// Derive a key using the SCP03 KDF
fn derive_key(parent_key: &[u8], derivation_constant: u8, context: &Context) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    kdf::derive(parent_key, derivation_constant, context, &mut key);
    key
}

/// Compute an "Initial Chaining Vector" (ICV) from a counter
fn compute_icv(cipher: &Aes128, counter: u32) -> GenericArray<u8, U16> {
    // "Initial Chaining Vector" - CBC IVs generated from encrypting a counter
    let mut icv = GenericArray::clone_from_slice(&[0u8; AES_BLOCK_SIZE]);
    icv.as_mut_slice()[12..].copy_from_slice(&counter.to_be_bytes());
    cipher.encrypt_block(&mut icv);
    icv
}

#[cfg(all(test, feature = "mockhsm"))]
mod tests {
    use super::*;
    use crate::authentication;

    const PASSWORD: &[u8] = b"password";
    const HOST_CHALLENGE: &[u8] = &[0u8; 8];
    const CARD_CHALLENGE: &[u8] = &[0u8; 8];
    const COMMAND_CODE: command::Code = command::Code::Echo;
    const COMMAND_DATA: &[u8] = b"Hello, world!";

    fn create_channel_pair() -> (SecureChannel, SecureChannel) {
        let authentication_key = authentication::Key::derive_from_password(PASSWORD);
        let host_challenge = Challenge::from_slice(HOST_CHALLENGE);
        let card_challenge = Challenge::from_slice(CARD_CHALLENGE);
        let session_id = session::Id::from_u8(0).unwrap();

        // Create channels
        let mut host_channel = SecureChannel::new(
            session_id,
            &authentication_key,
            host_challenge,
            card_challenge,
        );

        let mut card_channel = SecureChannel::new(
            session_id,
            &authentication_key,
            host_challenge,
            card_challenge,
        );

        // Auth host to card
        let auth_command = host_channel.authenticate_session().unwrap();
        let auth_response = card_channel
            .verify_authenticate_session(&auth_command)
            .unwrap();

        host_channel
            .finish_authenticate_session(&auth_response)
            .unwrap();

        (host_channel, card_channel)
    }

    #[test]
    fn happy_path_test() {
        let (mut host_channel, mut card_channel) = create_channel_pair();

        // Host sends encrypted command
        let command_ciphertext = host_channel
            .encrypt_command(
                command::Message::create(COMMAND_CODE, Vec::from(COMMAND_DATA)).unwrap(),
            )
            .unwrap();

        // Card decrypts command
        let decrypted_command = card_channel.decrypt_command(command_ciphertext).unwrap();

        // Card sends decrypted response
        let response_ciphertext = card_channel
            .encrypt_response(response::Message::success(
                decrypted_command.command_type,
                decrypted_command.data,
            ))
            .unwrap();

        let decrypted_response = host_channel.decrypt_response(response_ciphertext).unwrap();

        assert_eq!(host_channel.security_level, SecurityLevel::Authenticated);
        assert_eq!(decrypted_response.command().unwrap(), COMMAND_CODE);
        assert_eq!(&decrypted_response.data[..], COMMAND_DATA);
    }

    #[test]
    fn mac_verify_failure_test() {
        let (mut host_channel, mut card_channel) = create_channel_pair();

        // Host sends encrypted command
        let command_ciphertext = host_channel
            .encrypt_command(
                command::Message::create(COMMAND_CODE, Vec::from(COMMAND_DATA)).unwrap(),
            )
            .unwrap();

        // Card decrypts command
        let decrypted_command = card_channel.decrypt_command(command_ciphertext).unwrap();

        // Card sends decrypted response
        let mut response_ciphertext = card_channel
            .encrypt_response(response::Message::success(
                decrypted_command.command_type,
                decrypted_command.data,
            ))
            .unwrap();

        // Tweak MAC in response
        let mut bad_mac = Vec::from(response_ciphertext.mac.as_ref().unwrap().as_slice());
        bad_mac[0] ^= 0xAA;
        response_ciphertext.mac = Some(Mac::from_slice(&bad_mac));

        let response = host_channel.decrypt_response(response_ciphertext);
        assert!(response.is_err());
        assert_eq!(host_channel.security_level, SecurityLevel::Terminated);
        assert_eq!(
            response.err().unwrap().to_string(),
            "cryptographic verification failed: R-MAC mismatch!"
        );
    }
}
