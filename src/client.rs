//! YubiHSM client: core functionality of this crate.
//!
//! The `Client` type provides a set of methods which map to commands which
//! interface with the HSM.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

#![allow(clippy::too_many_arguments)]

#[macro_use]
mod error;

pub use self::error::{Error, ErrorKind};

use crate::{
    asymmetric::{self, commands::*, PublicKey},
    attestation::{self, commands::*},
    audit::{commands::*, *},
    authentication::{self, commands::*, Credentials},
    capability::Capability,
    command::{self, Command},
    connector::Connector,
    device::{self, commands::*, StorageInfo},
    domain::Domain,
    ecdsa::commands::*,
    ed25519::{self, commands::*},
    hmac::{self, commands::*},
    object::{self, commands::*, generate},
    opaque::{self, commands::*},
    otp::{self, commands::*},
    rsa::{self, oaep::commands::*},
    serialization::{deserialize, serialize},
    session::{self, Session},
    template::{commands::*, Template},
    uuid,
    wrap::{self, commands::*},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(feature = "passwords")]
use std::{thread, time::SystemTime};

#[cfg(feature = "yubihsm-auth")]
use crate::session::PendingSession;

#[cfg(feature = "untested")]
use {
    crate::{
        algorithm::Algorithm,
        ecdh::{self, commands::*},
        rsa::{pkcs1::commands::*, pss::commands::*},
        ssh::{self, commands::*},
    },
    sha2::{Digest, Sha256},
};

#[cfg(any(doc, docsrs))]
use crate::ecdsa;

/// YubiHSM client: main API in this crate for accessing functions of the
/// HSM hardware device.
#[derive(Clone)]
pub struct Client {
    /// Connector for communicating with the HSM
    connector: Connector,

    /// Encrypted session with the HSM (if we have one open)
    session: Arc<Mutex<Option<Session>>>,

    /// Cached `Credentials` for reconnecting closed sessions
    credentials: Option<Credentials>,
}

impl Client {
    /// Open a connection via a [Connector] to a YubiHSM, returning a `yubihsm::Client`.
    /// Valid `Connector` types are: [HttpConnector], [UsbConnector], and [MockHsm].
    ///
    /// [Connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/index.html
    /// [HttpConnector]: https://docs.rs/yubihsm/latest/yubihsm/connector/http/struct.HttpConnector.html
    /// [UsbConnector]: https://docs.rs/yubihsm/latest/yubihsm/connector/usb/struct.UsbConnector.html
    /// [MockHsm]: https://docs.rs/yubihsm/latest/yubihsm/mockhsm/struct.MockHsm.html
    pub fn open(
        connector: Connector,
        credentials: Credentials,
        reconnect: bool,
    ) -> Result<Self, Error> {
        let mut client = Self::create(connector, credentials)?;
        client.connect()?;

        // Clear credentials if reconnecting has been disabled
        if !reconnect {
            client.credentials = None;
        }

        Ok(client)
    }

    /// Create a `yubihsm::Client`, but defer connecting until `connect()` is called.
    pub fn create(connector: Connector, credentials: Credentials) -> Result<Self, Error> {
        let client = Self {
            connector,
            session: Arc::new(Mutex::new(None)),
            credentials: Some(credentials),
        };

        Ok(client)
    }

    /// Open session with YubiHSM Auth scheme
    #[cfg(feature = "yubihsm-auth")]
    pub fn yubihsm_auth(
        connector: Connector,
        authentication_key_id: object::Id,
        host_challenge: session::securechannel::Challenge,
    ) -> Result<PendingSession, Error> {
        let timeout = session::Timeout::default();

        let session =
            PendingSession::new(connector, timeout, authentication_key_id, host_challenge)?;
        Ok(session)
    }

    /// Borrow this client's YubiHSM connector (which is `Clone`able)
    pub fn connector(&self) -> &Connector {
        &self.connector
    }

    /// Connect to the HSM (idempotently, i.e. returns success if we have
    /// an open connection already)
    pub fn connect(&self) -> Result<(), Error> {
        self.session()?;
        Ok(())
    }

    /// Get current `Session` (either opening a new one or returning an already
    /// open one).
    pub fn session(&self) -> Result<session::Guard<'_>, Error> {
        // TODO(tarcieri): handle PoisonError better?
        let mut session_mutex_guard = self.session.lock().unwrap();

        if let Some(session) = session_mutex_guard.as_ref() {
            if session.is_open() {
                return Ok(session::Guard::new(session_mutex_guard));
            }
        }

        // If we don't have an open session, create a new one
        let session = Session::open(
            self.connector.clone(),
            self.credentials.as_ref().ok_or_else(|| {
                format_err!(
                    ErrorKind::AuthenticationError,
                    "session reconnection disabled"
                )
            })?,
            session::Timeout::default(),
        )?;

        *session_mutex_guard = Some(session);
        Ok(session::Guard::new(session_mutex_guard))
    }

    /// Ping the HSM, ensuring we have a live connection and returning the
    /// end-to-end latency.
    pub fn ping(&self) -> Result<Duration, Error> {
        let t = Instant::now();
        let uuid = uuid::new_v4().to_string();
        let response = self.echo(uuid.as_bytes())?;

        ensure!(
            uuid.as_bytes() == response.as_slice(),
            ErrorKind::ResponseError,
            "expected {}, got {}",
            uuid,
            String::from_utf8_lossy(&response)
        );

        Ok(Instant::now().duration_since(t))
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response.
    fn send_command<T: Command>(&self, command: T) -> Result<T::ResponseType, Error> {
        let mut session = self.session()?;

        match session.send_command(&command) {
            Ok(response) => Ok(response),
            Err(err) if *err.kind() == session::ErrorKind::CommandLimitExceeded => {
                // If we encounter this, we've exceeded the maximum number of
                // messages allowed under the data volume limits and need to
                // rekey the connection by creating a new session.

                // Drop the stale `session::Guard` to release the session mutex.
                drop(session);

                // Attempt to initiate a new session and retry the command.
                // (the original command was never sent in this case)
                Ok(self.session()?.send_command(&command)?)
            }
            Err(err) => Err(err.into()),
        }
    }

    //
    // HSM Commands
    // <https://developers.yubico.com/YubiHSM2/Commands/>
    //

    /// Blink the HSM's LEDs (to identify it) for the given number of seconds.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Blink_Device.html>
    pub fn blink_device(&self, num_seconds: u8) -> Result<(), Error> {
        self.send_command(BlinkDeviceCommand { num_seconds })?;
        Ok(())
    }

    /// Decrypt data encrypted with RSA-OAEP
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Decrypt_Oaep.html>
    pub fn decrypt_oaep<T>(
        &self,
        key_id: object::Id,
        mgf1_hash_alg: rsa::mgf::Algorithm,
        data: T,
        label_hash: Vec<u8>,
    ) -> Result<rsa::oaep::DecryptedData, Error>
    where
        T: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(DecryptOaepCommand {
                key_id,
                mgf1_hash_alg,
                data: data.into(),
                label_hash,
            })?
            .into())
    }

    /// Delete an object of the given ID and type.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
    pub fn delete_object(
        &self,
        object_id: object::Id,
        object_type: object::Type,
    ) -> Result<(), Error> {
        self.send_command(DeleteObjectCommand {
            object_id,
            object_type,
        })?;
        Ok(())
    }

    /// Elliptic Curve Diffie-Hellman: derive a shared secret via key exchange.
    ///
    /// **WARNING**: This functionality has not been tested and has not yet been
    /// confirmed to actually work! USE AT YOUR OWN RISK!
    ///
    /// You will need to enable the `untested` cargo feature to use it.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Derive_Ecdh.html>
    #[cfg(feature = "untested")]
    pub fn derive_ecdh(
        &self,
        key_id: object::Id,
        public_key: ecdh::UncompressedPoint,
    ) -> Result<ecdh::UncompressedPoint, Error> {
        Ok(self
            .send_command(DeriveEcdhCommand { key_id, public_key })?
            .into())
    }

    /// Get information about the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Device_Info.html>
    pub fn device_info(&self) -> Result<device::Info, Error> {
        Ok(self.send_command(DeviceInfoCommand {})?.into())
    }

    /// Echo a message sent to the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
    pub fn echo<M>(&self, msg: M) -> Result<Vec<u8>, Error>
    where
        M: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(EchoCommand {
                message: msg.into(),
            })?
            .0)
    }

    /// Export an encrypted object from the HSM using the given key-wrapping key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrapped.html>
    pub fn export_wrapped(
        &self,
        wrap_key_id: object::Id,
        object_type: object::Type,
        object_id: object::Id,
    ) -> Result<wrap::Message, Error> {
        Ok(self
            .send_command(ExportWrappedCommand {
                wrap_key_id,
                object_type,
                object_id,
            })?
            .0)
    }

    /// Generate a new asymmetric key within the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
    pub fn generate_asymmetric_key(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: asymmetric::Algorithm,
    ) -> Result<object::Id, Error> {
        Ok(self
            .send_command(GenAsymmetricKeyCommand(generate::Params {
                key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            }))?
            .key_id)
    }

    /// Generate a new HMAC key within the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Hmac_Key.html>
    pub fn generate_hmac_key(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: hmac::Algorithm,
    ) -> Result<object::Id, Error> {
        Ok(self
            .send_command(GenHmacKeyCommand(generate::Params {
                key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            }))?
            .key_id)
    }

    /// Generate a new wrap key within the HSM.
    ///
    /// Delegated capabilities are the set of `Capability` bits that an object is allowed to have
    /// when imported or exported using the wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Wrap_Key.html>
    pub fn generate_wrap_key(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: wrap::Algorithm,
    ) -> Result<object::Id, Error> {
        Ok(self
            .send_command(GenWrapKeyCommand {
                params: generate::Params {
                    key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
            })?
            .key_id)
    }

    /// Get audit logs from the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html>
    pub fn get_log_entries(&self) -> Result<LogEntries, Error> {
        self.send_command(GetLogEntriesCommand {})
    }

    /// Get information about an object.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
    pub fn get_object_info(
        &self,
        object_id: object::Id,
        object_type: object::Type,
    ) -> Result<object::Info, Error> {
        Ok(self
            .send_command(GetObjectInfoCommand(object::Handle::new(
                object_id,
                object_type,
            )))?
            .0)
    }

    /// Get an opaque object stored in the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Opaque.html>
    pub fn get_opaque(&self, object_id: object::Id) -> Result<Vec<u8>, Error> {
        Ok(self.send_command(GetOpaqueCommand { object_id })?.0)
    }

    /// Get the audit policy setting for a particular command.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    pub fn get_command_audit_option(&self, command: command::Code) -> Result<AuditOption, Error> {
        let command_audit_options = self.get_commands_audit_options()?;
        Ok(command_audit_options
            .iter()
            .find(|opt| opt.command_type() == command)
            .map(AuditCommand::audit_option)
            .unwrap_or(AuditOption::Off))
    }

    /// Get the audit policy settings for all commands.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    pub fn get_commands_audit_options(&self) -> Result<Vec<AuditCommand>, Error> {
        let response = self.send_command(GetOptionCommand {
            tag: AuditTag::Command,
        })?;

        Ok(deserialize(&response.0)?)
    }

    /// Get the forced auditing global option: when enabled, the device will
    /// refuse operations if the [log store] becomes full.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    ///
    /// [log store]: https://developers.yubico.com/YubiHSM2/Concepts/Logs.html
    pub fn get_force_audit_option(&self) -> Result<AuditOption, Error> {
        let response = self.send_command(GetOptionCommand {
            tag: AuditTag::Force,
        })?;

        ensure!(
            response.0.len() == 1,
            ErrorKind::ProtocolError,
            "expected 1-byte response, got {}",
            response.0.len()
        );

        AuditOption::from_u8(response.0[0])
            .map_err(|e| format_err!(ErrorKind::ProtocolError, e).into())
    }

    /// Get the FIPS operation global option
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    pub fn get_fips_option(&self) -> Result<AuditOption, Error> {
        let response = self.send_command(GetOptionCommand {
            tag: AuditTag::Fips,
        })?;

        ensure!(
            response.0.len() == 1,
            ErrorKind::ProtocolError,
            "expected 1-byte response, got {}",
            response.0.len()
        );

        AuditOption::from_u8(response.0[0])
            .map_err(|e| format_err!(ErrorKind::ProtocolError, e).into())
    }

    /// Get some number of bytes of pseudo random data generated on the device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html>
    pub fn get_pseudo_random(&self, bytes: usize) -> Result<Vec<u8>, Error> {
        ensure!(
            bytes <= MAX_RAND_BYTES,
            ErrorKind::ProtocolError,
            "requested number of bytes too large: {} (max: {})",
            bytes,
            MAX_RAND_BYTES
        );

        Ok(self
            .send_command(GetPseudoRandomCommand {
                bytes: bytes as u16,
            })?
            .bytes)
    }

    /// Get the public key for an asymmetric key stored on the device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Public_Key.html>
    pub fn get_public_key(&self, key_id: object::Id) -> Result<PublicKey, Error> {
        Ok(self.send_command(GetPublicKeyCommand { key_id })?.into())
    }

    /// Get storage info (i.e. currently free storage) from the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Storage_Info.html>
    pub fn get_storage_info(&self) -> Result<StorageInfo, Error> {
        Ok(self.send_command(GetStorageInfoCommand {})?.into())
    }

    /// Get a certificate template (i.e. for SSH CA) stored in the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Template.html>
    pub fn get_template(&self, object_id: object::Id) -> Result<Vec<u8>, Error> {
        Ok(self.send_command(GetTemplateCommand { object_id })?.0)
    }

    /// Import an encrypted object from the HSM using the given key-wrapping key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Import_Wrapped.html>
    pub fn import_wrapped<M>(
        &self,
        wrap_key_id: object::Id,
        wrap_message: M,
    ) -> Result<object::Handle, Error>
    where
        M: Into<wrap::Message>,
    {
        let wrap::Message { nonce, ciphertext } = wrap_message.into();

        let response = self.send_command(ImportWrappedCommand {
            wrap_key_id,
            nonce,
            ciphertext,
        })?;

        Ok(object::Handle::new(
            response.object_id,
            response.object_type,
        ))
    }

    /// List objects visible from the current session.
    ///
    /// Optionally apply a set of provided `filters` which select objects
    /// based on their attributes.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
    pub fn list_objects(&self, filters: &[object::Filter]) -> Result<Vec<object::Entry>, Error> {
        let mut filter_bytes = vec![];

        for filter in filters {
            filter.serialize(&mut filter_bytes)?;
        }

        Ok(self.send_command(ListObjectsCommand(filter_bytes))?.0)
    }

    /// Put an existing asymmetric key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric.html>
    pub fn put_asymmetric_key<K>(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: asymmetric::Algorithm,
        key_bytes: K,
    ) -> Result<object::Id, Error>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ErrorKind::ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutAsymmetricKeyCommand {
                params: object::put::Params {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data,
            })?
            .key_id)
    }

    /// Put an existing `authentication::Key` into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Authentication_Key.html>
    pub fn put_authentication_key<K>(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: authentication::Algorithm,
        authentication_key: K,
    ) -> Result<object::Id, Error>
    where
        K: Into<authentication::Key>,
    {
        Ok(self
            .send_command(PutAuthenticationKeyCommand {
                params: object::put::Params {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
                authentication_key: authentication_key.into(),
            })?
            .key_id)
    }

    /// Put an existing HMAC key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>
    pub fn put_hmac_key<K>(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: hmac::Algorithm,
        key_bytes: K,
    ) -> Result<object::Id, Error>
    where
        K: Into<Vec<u8>>,
    {
        let hmac_key = key_bytes.into();

        if hmac_key.len() < HMAC_MIN_KEY_SIZE || hmac_key.len() > algorithm.max_key_len() {
            fail!(
                ErrorKind::ProtocolError,
                "invalid key length for {:?}: {} (min {}, max {})",
                algorithm,
                hmac_key.len(),
                HMAC_MIN_KEY_SIZE,
                algorithm.max_key_len()
            );
        }

        Ok(self
            .send_command(PutHmacKeyCommand {
                params: object::put::Params {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                hmac_key,
            })?
            .key_id)
    }

    /// Put an opaque object (X.509 certificate or other bytestring) into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html>
    pub fn put_opaque<B>(
        &self,
        object_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: opaque::Algorithm,
        opaque_data: B,
    ) -> Result<object::Id, Error>
    where
        B: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(PutOpaqueCommand {
                params: object::put::Params {
                    id: object_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data: opaque_data.into(),
            })?
            .object_id)
    }

    /// Put an existing OTP AEAD key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Otp_Aead_Key.html>
    pub fn put_otp_aead_key<K>(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        algorithm: otp::Algorithm,
        key_bytes: K,
    ) -> Result<object::Id, Error>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ErrorKind::ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutOtpAeadKeyCommand {
                params: object::put::Params {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data,
            })?
            .key_id)
    }

    /// Put an existing wrap key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap_Key.html>
    pub fn put_wrap_key<K>(
        &self,
        key_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: wrap::Algorithm,
        key_bytes: K,
    ) -> Result<object::Id, Error>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ErrorKind::ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutWrapKeyCommand {
                params: object::put::Params {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
                data,
            })?
            .key_id)
    }

    /// Put a template object (i.e. for SSH CA) into the HSM.
    ///
    /// Use the `yubihsm::ssh::Template` type for SSH CA templates.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Template.html>
    pub fn put_template<T>(
        &self,
        object_id: object::Id,
        label: object::Label,
        domains: Domain,
        capabilities: Capability,
        template: T,
    ) -> Result<object::Id, Error>
    where
        T: Into<Template>,
    {
        let template: Template = template.into();

        Ok(self
            .send_command(PutTemplateCommand {
                params: object::put::Params {
                    id: object_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: template.algorithm().into(),
                },
                data: template.as_ref().into(),
            })?
            .object_id)
    }

    /// Reset the HSM to a factory default state and reboot, clearing all
    /// stored objects and restoring the default auth key.
    ///
    /// **WARNING:** This wipes all keys and other data from the HSM! Make
    /// absolutely sure you want to use this!
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html>
    pub fn reset_device(&self) -> Result<(), Error> {
        let mut session = self.session()?;

        // TODO: handle potential errors that occur when resetting
        if let Err(e) = session.send_command(&ResetDeviceCommand {}) {
            debug!("error sending reset command: {}", e);
        }

        // Resetting the HSM invalidates our session
        session.abort();
        Ok(())
    }

    /// Reset the HSM to a factory default state and reboot, clearing all
    /// stored objects and restoring the default auth key. This method further
    /// attempts to wait for the HSM to finish resetting and then attempts to
    /// reauthenticate with the default credentials.
    ///
    /// Upon successfully resetting the device and autenticating using the
    /// default administrator credentials in key slot 0x01, a new
    /// `yubihsm::Client` is returned.
    ///
    /// **WARNING:** This wipes all keys and other data from the HSM! Make
    /// absolutely sure you want to use this!
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html>
    #[cfg(feature = "passwords")]
    pub fn reset_device_and_reconnect(&mut self, timeout: Duration) -> Result<(), Error> {
        /// How long to initially wait for a device reset to complete (1s)
        const DEVICE_RESET_WAIT_MS: u64 = 1000;

        /// How frequently to poll the device after it's been reset (200ms)
        const DEVICE_POLL_INTERVAL_MS: u64 = 200;

        // Warn people and give them a brief grace period to avoid oblitering their HSM
        warn!("factory resetting HSM device! all data will be lost!");
        thread::sleep(Duration::from_millis(DEVICE_RESET_WAIT_MS));

        // Reset the device. This will invalidate the previous session.
        self.reset_device()?;

        // Configure default credentials
        self.credentials = Some(Credentials::default());

        let deadline = SystemTime::now() + timeout;

        info!("waiting for device reset to complete");
        thread::sleep(Duration::from_millis(DEVICE_RESET_WAIT_MS));

        // Attempt to reconnect to the device with the default credentials
        loop {
            match self.connect() {
                Ok(_) => {
                    debug!("successfully reconnected to HSM after reset!");
                    return Ok(());
                }
                Err(e) => {
                    // If we're past the deadline, return an error
                    if SystemTime::now() >= deadline {
                        fail!(
                            ErrorKind::CreateFailed,
                            "timed out after {} seconds connecting to HSM after reset: {}",
                            timeout.as_secs(),
                            e
                        )
                    } else {
                        debug!("error reconnecting to HSM: {}", e);
                        thread::sleep(Duration::from_millis(DEVICE_POLL_INTERVAL_MS))
                    }
                }
            }
        }
    }

    /// Configure the audit policy settings for a particular command, e.g. auditing
    /// should be `On`, `Off`, or `Fix` (i.e. fixed permanently on).
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Set_Option.html>
    pub fn set_command_audit_option(
        &self,
        command: command::Code,
        audit_option: AuditOption,
    ) -> Result<(), Error> {
        self.send_command(SetOptionCommand {
            tag: AuditTag::Command,
            length: 2,
            value: serialize(&AuditCommand(command, audit_option))?,
        })?;

        Ok(())
    }

    /// Put the forced auditing global option: when enabled, the device will
    /// refuse operations if the [log store] becomes full.
    ///
    /// Options are `On`, `Off`, or `Fix` (i.e. fixed permanently on)
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>
    ///
    /// [log store]: https://developers.yubico.com/YubiHSM2/Concepts/Logs.html
    pub fn set_force_audit_option(&self, option: AuditOption) -> Result<(), Error> {
        self.send_command(SetOptionCommand {
            tag: AuditTag::Force,
            length: 1,
            value: vec![option.to_u8()],
        })?;

        Ok(())
    }

    /// Put the FIPS global option: when enabled, it disables algorithms that are
    /// not allowed by FIPS 140.
    ///
    /// Options are `Off`, or `On`
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>
    pub fn set_fips_option(&self, option: AuditOption) -> Result<(), Error> {
        self.send_command(SetOptionCommand {
            tag: AuditTag::Fips,
            length: 1,
            value: vec![option.to_u8()],
        })?;

        Ok(())
    }

    /// Set the index of the last consumed index of the HSM audit log.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Set_Log_Index.html>
    pub fn set_log_index(&self, log_index: u16) -> Result<(), Error> {
        self.send_command(SetLogIndexCommand { log_index })?;
        Ok(())
    }

    /// Obtain an X.509 attestation certificate for a key within the HSM.
    /// This can be used to demonstrate that a given key was generated by
    /// and stored within a HSM in a non-exportable manner.
    ///
    /// The `key_id` is the subject key for which an attestation certificate
    /// is created, and the`attestation_key_id` will be used to sign the
    /// attestation certificate.
    ///
    /// If no attestation key is given, the device's default attestation key
    /// will be used, and can be verified against Yubico's certificate.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Attestation_Certificate.html>
    pub fn sign_attestation_certificate(
        &self,
        key_id: object::Id,
        attestation_key_id: Option<object::Id>,
    ) -> Result<attestation::Certificate, Error> {
        self.send_command(SignAttestationCertificateCommand {
            key_id,
            attestation_key_id: attestation_key_id.unwrap_or(0),
        })
    }

    /// Compute an ECDSA signature of the given digest (i.e. a precomputed SHA-2 digest)
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Ecdsa.html>
    ///
    /// # Security Warning
    ///
    /// This is a low-level ECDSA API, and if used incorrectly could potentially
    /// result in forgeable signatures.
    ///
    /// We recommend using the [`ecdsa::Signer`] type instead, which provides a
    /// high-level, well-typed, misuse resistant API.
    pub fn sign_ecdsa_prehash_raw<T>(&self, key_id: object::Id, digest: T) -> Result<Vec<u8>, Error>
    where
        T: Into<Vec<u8>>,
    {
        self.send_command(SignEcdsaCommand {
            key_id,
            digest: digest.into(),
        })
        .map(Into::into)
    }

    /// Compute an Ed25519 signature with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html>
    pub fn sign_ed25519<T>(&self, key_id: object::Id, data: T) -> Result<ed25519::Signature, Error>
    where
        T: Into<Vec<u8>>,
    {
        self.send_command(SignEddsaCommand {
            key_id,
            data: data.into(),
        })?
        .signature()
    }

    /// Compute an HMAC tag of the given data with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Hmac.html>
    pub fn sign_hmac<M>(&self, key_id: object::Id, msg: M) -> Result<hmac::Tag, Error>
    where
        M: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(SignHmacCommand {
                key_id,
                data: msg.into(),
            })?
            .into())
    }

    /// Compute an RSASSA-PKCS#1v1.5 signature of the SHA-256 hash of the given data.
    ///
    /// **WARNING**: This functionality has not been tested and has not yet been
    /// confirmed to actually work! USE AT YOUR OWN RISK!
    ///
    /// You will need to enable the `untested` cargo feature to use it.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Pkcs1.html>
    #[cfg(feature = "untested")]
    pub fn sign_rsa_pkcs1v15_sha256(
        &self,
        key_id: object::Id,
        data: &[u8],
    ) -> Result<rsa::pkcs1::Signature, Error> {
        Ok(self
            .send_command(SignPkcs1Command {
                key_id,
                digest: Sha256::digest(data).as_slice().into(),
            })?
            .into())
    }

    /// Compute an RSASSA-PSS signature of the SHA-256 hash of the given data with the given key ID.
    ///
    /// **WARNING**: This functionality has not been tested and has not yet been
    /// confirmed to actually work! USE AT YOUR OWN RISK!
    ///
    /// You will need to enable the `untested` cargo feature to use it.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Pss.html>
    #[cfg(feature = "untested")]
    pub fn sign_rsa_pss_sha256(
        &self,
        key_id: object::Id,
        data: &[u8],
    ) -> Result<rsa::pss::Signature, Error> {
        ensure!(
            data.len() > rsa::pss::MAX_MESSAGE_SIZE,
            ErrorKind::ProtocolError,
            "message too large to be signed (max: {})",
            rsa::pss::MAX_MESSAGE_SIZE
        );

        let mut hasher = Sha256::default();

        let length = data.len() as u16;
        hasher.update(length.to_be_bytes());
        hasher.update(data);
        let digest = hasher.finalize();

        Ok(self
            .send_command(SignPssCommand {
                key_id,
                mgf1_hash_alg: rsa::mgf::Algorithm::Sha256,
                salt_len: digest.as_slice().len() as u16,
                digest: digest.as_slice().into(),
            })?
            .into())
    }

    /// Sign an SSH certificate using the given template.
    ///
    /// **WARNING**: This functionality has not been tested and has not yet been
    /// confirmed to actually work! USE AT YOUR OWN RISK!
    ///
    /// You will need to enable the `untested` cargo feature to use it.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Ssh_Certificate.html>
    #[cfg(feature = "untested")]
    pub fn sign_ssh_certificate<A>(
        &self,
        key_id: object::Id,
        template_id: object::Id,
        algorithm: A,
        timestamp: u32,
        signature: [u8; 32],
        request: Vec<u8>,
    ) -> Result<ssh::Certificate, Error>
    where
        A: Into<Algorithm>,
    {
        Ok(self
            .send_command(SignSshCertificateCommand {
                key_id,
                template_id,
                algorithm: algorithm.into(),
                timestamp,
                signature,
                request,
            })?
            .into())
    }

    /// Decrypt data which was encrypted (using AES-CCM) under a wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Unwrap_Data.html>
    pub fn unwrap_data<M>(&self, wrap_key_id: object::Id, wrap_message: M) -> Result<Vec<u8>, Error>
    where
        M: Into<wrap::Message>,
    {
        let wrap::Message { nonce, ciphertext } = wrap_message.into();

        Ok(self
            .send_command(UnwrapDataCommand {
                wrap_key_id,
                nonce,
                ciphertext,
            })?
            .0)
    }

    /// Verify an HMAC tag of the given data with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Verify_Hmac.html>
    pub fn verify_hmac<M, T>(&self, key_id: object::Id, msg: M, tag: T) -> Result<(), Error>
    where
        M: Into<Vec<u8>>,
        T: Into<hmac::Tag>,
    {
        let result = self.send_command(VerifyHmacCommand {
            key_id,
            tag: tag.into(),
            data: msg.into(),
        })?;

        if result.0 == 0 {
            fail!(ErrorKind::ResponseError, "HMAC verification failure")
        }

        Ok(())
    }

    /// Encrypt data (with AES-CCM) using the given wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html>
    pub fn wrap_data(
        &self,
        wrap_key_id: object::Id,
        plaintext: Vec<u8>,
    ) -> Result<wrap::Message, Error> {
        Ok(self
            .send_command(WrapDataCommand {
                wrap_key_id,
                plaintext,
            })?
            .0)
    }
}

impl From<Session> for Client {
    fn from(session: Session) -> Self {
        let connector = session.connector();
        let session = Arc::new(Mutex::new(Some(session)));
        Self {
            connector,
            session,
            credentials: None,
        }
    }
}
