//! YubiHSM client: core functionality of this crate.
//!
//! The `Client` type provides a set of methods which map to commands which
//! interface with the HSM.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

#[macro_use]
mod error;

mod attest_asymmetric;
mod blink;
mod delete_object;
mod device_info;
mod echo;
mod export_wrapped;
mod generate_asymmetric_key;
mod generate_hmac_key;
mod generate_key;
mod generate_wrap_key;
mod get_logs;
mod get_object_info;
mod get_opaque;
mod get_option;
mod get_pseudo_random;
mod get_pubkey;
mod hmac;
mod import_wrapped;
mod list_objects;
mod put_asymmetric_key;
mod put_auth_key;
mod put_hmac_key;
mod put_object;
mod put_opaque;
mod put_option;
mod put_otp_aead_key;
mod put_wrap_key;
mod reset;
mod set_log_index;
mod sign_ecdsa;
mod sign_eddsa;
#[cfg(feature = "rsa")]
mod sign_rsa_pkcs1v15;
#[cfg(feature = "rsa")]
mod sign_rsa_pss;
mod storage_status;
mod unwrap_data;
mod verify_hmac;
mod wrap_data;

#[cfg(feature = "rsa")]
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub use self::error::{ClientError, ClientErrorKind};

use self::error::ClientErrorKind::*;
pub use self::{
    attest_asymmetric::*, device_info::*, get_logs::*, get_pubkey::*, hmac::*, import_wrapped::*,
    list_objects::*, reset::*, sign_ecdsa::*, sign_eddsa::*, storage_status::*,
};
pub(crate) use self::{
    blink::*, delete_object::*, echo::*, export_wrapped::*, generate_asymmetric_key::*,
    generate_hmac_key::*, generate_key::*, generate_wrap_key::*, get_object_info::*, get_opaque::*,
    get_option::*, get_pseudo_random::*, put_asymmetric_key::*, put_auth_key::*, put_hmac_key::*,
    put_object::*, put_opaque::*, put_option::*, put_otp_aead_key::*, put_wrap_key::*,
    set_log_index::*, unwrap_data::*, verify_hmac::*, wrap_data::*,
};
#[cfg(feature = "rsa")]
pub use self::{sign_rsa_pkcs1v15::*, sign_rsa_pss::*};
use algorithm::*;
use audit::*;
use auth_key::AuthKey;
#[cfg(feature = "rsa")]
use byteorder::{BigEndian, ByteOrder};
use capability::Capability;
use command::{Command, CommandCode};
use connector::Connector;
use credentials::Credentials;
use domain::Domain;
use object::{ObjectHandle, ObjectId, ObjectInfo, ObjectLabel, ObjectType};
use serialization::{deserialize, serialize};
use session::{Session, SessionId, SessionTimeout};
use wrap::WrapMessage;

/// YubiHSM client: main API in this crate for accessing functions of the
/// HSM hardware device.
pub struct Client {
    /// Method for connecting to the HSM
    connector: Box<Connector>,

    /// Encrypted session with the HSM (if we have one open)
    session: Option<Session>,

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
    pub fn open<C>(
        connector: C,
        credentials: Credentials,
        reconnect: bool,
    ) -> Result<Self, ClientError>
    where
        C: Into<Box<Connector>>,
    {
        let mut client = Self::new(connector, credentials)?;
        client.connect()?;

        // Clear credentials if reconnecting has been disabled
        if !reconnect {
            client.credentials = None;
        }

        Ok(client)
    }

    /// Create a `yubihsm::Client`, but defer connecting until `connect()` is called.
    pub fn new<C>(connector: C, credentials: Credentials) -> Result<Self, ClientError>
    where
        C: Into<Box<Connector>>,
    {
        let client = Self {
            connector: connector.into(),
            session: None,
            credentials: Some(credentials),
        };

        Ok(client)
    }

    /// Connect to the HSM (idempotently, i.e. returns success if we have
    /// an open connection already)
    pub fn connect(&mut self) -> Result<(), ClientError> {
        self.session()?;
        Ok(())
    }

    /// Are we currently connected to the HSM?
    pub fn is_connected(&self) -> bool {
        self.session.as_ref().map(Session::is_open).unwrap_or(false)
    }

    /// Get the current session ID (if we have an open session).
    pub fn session_id(&self) -> Option<SessionId> {
        self.session.as_ref().and_then(|s| Some(s.id()))
    }

    /// Get current `Session` (either opening a new one or returning an already
    /// open one).
    pub fn session(&mut self) -> Result<&mut Session, ClientError> {
        if self.is_connected() {
            return Ok(self.session.as_mut().unwrap());
        }

        let session = Session::open(
            &*self.connector,
            self.credentials
                .as_ref()
                .ok_or_else(|| err!(AuthFail, "session reconnection disabled"))?,
            SessionTimeout::default(),
        )?;

        self.session = Some(session);
        Ok(self.session.as_mut().unwrap())
    }

    /// Ping the HSM, ensuring we have a live connection and returning the
    /// end-to-end latency.
    pub fn ping(&mut self) -> Result<Duration, ClientError> {
        let t = Instant::now();
        let uuid = Uuid::new_v4().to_hyphenated().to_string();
        let response = self.echo(uuid.as_bytes())?;

        ensure!(
            uuid.as_bytes() == response.as_slice(),
            ResponseError,
            "expected {}, got {}",
            uuid,
            String::from_utf8_lossy(&response)
        );

        Ok(Instant::now().duration_since(t))
    }

    /// Encrypt a command, send it to the HSM, then read and decrypt the response.
    fn send_command<T: Command>(&mut self, command: T) -> Result<T::ResponseType, ClientError> {
        Ok(self.session()?.send_command(command)?)
    }

    //
    // HSM Commands
    // <https://developers.yubico.com/YubiHSM2/Commands/>
    //

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
    /// <https://developers.yubico.com/YubiHSM2/Commands/Attest_Asymmetric.html>
    pub fn attest_asymmetric(
        &mut self,
        key_id: ObjectId,
        attestation_key_id: Option<ObjectId>,
    ) -> Result<AttestationCertificate, ClientError> {
        Ok(self.send_command(AttestAsymmetricCommand {
            key_id,
            attestation_key_id: attestation_key_id.unwrap_or(0),
        })?)
    }

    /// Blink the HSM's LEDs (to identify it) for the given number of seconds.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>
    pub fn blink(&mut self, num_seconds: u8) -> Result<(), ClientError> {
        self.send_command(BlinkCommand { num_seconds })?;
        Ok(())
    }

    /// Delete an object of the given ID and type.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
    pub fn delete_object(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
    ) -> Result<(), ClientError> {
        self.send_command(DeleteObjectCommand {
            object_id,
            object_type,
        })?;
        Ok(())
    }

    /// Get information about the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Device_Info.html>
    pub fn device_info(&mut self) -> Result<DeviceInfoResponse, ClientError> {
        Ok(self.send_command(DeviceInfoCommand {})?)
    }

    /// Echo a message sent to the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
    pub fn echo<M>(&mut self, msg: M) -> Result<Vec<u8>, ClientError>
    where
        M: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(EchoCommand {
                message: msg.into(),
            })?.0)
    }

    /// Export an encrypted object from the HSM using the given key-wrapping key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrapped.html>
    pub fn export_wrapped(
        &mut self,
        wrap_key_id: ObjectId,
        object_type: ObjectType,
        object_id: ObjectId,
    ) -> Result<WrapMessage, ClientError> {
        Ok(self
            .send_command(ExportWrappedCommand {
                wrap_key_id,
                object_type,
                object_id,
            })?.0)
    }

    /// Generate a new asymmetric key within the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
    pub fn generate_asymmetric_key(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: AsymmetricAlg,
    ) -> Result<ObjectId, ClientError> {
        Ok(self
            .send_command(GenAsymmetricKeyCommand(GenerateKeyParams {
                key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            }))?.key_id)
    }

    /// Generate a new HMAC key within the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Hmac_Key.html>
    pub fn generate_hmac_key(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: HmacAlg,
    ) -> Result<ObjectId, ClientError> {
        Ok(self
            .send_command(GenHMACKeyCommand(GenerateKeyParams {
                key_id,
                label,
                domains,
                capabilities,
                algorithm: algorithm.into(),
            }))?.key_id)
    }

    /// Generate a new wrap key within the HSM.
    ///
    /// Delegated capabilities are the set of `Capability` bits that an object is allowed to have
    /// when imported or exported using the wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Wrap_Key.html>
    pub fn generate_wrap_key(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: WrapAlg,
    ) -> Result<ObjectId, ClientError> {
        Ok(self
            .send_command(GenWrapKeyCommand {
                params: GenerateKeyParams {
                    key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
            })?.key_id)
    }

    /// Get audit logs from the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Logs.html>
    pub fn get_audit_logs(&mut self) -> Result<AuditLogs, ClientError> {
        Ok(self.send_command(GetLogsCommand {})?)
    }

    /// Get information about an object.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
    pub fn get_object_info(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
    ) -> Result<ObjectInfo, ClientError> {
        Ok(self
            .send_command(GetObjectInfoCommand(ObjectHandle::new(
                object_id,
                object_type,
            )))?.0)
    }

    /// Get an opaque object stored in the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Opaque.html>
    pub fn get_opaque(&mut self, object_id: ObjectId) -> Result<Vec<u8>, ClientError> {
        Ok(self.send_command(GetOpaqueCommand { object_id })?.0)
    }

    /// Get the audit policy setting for a particular command.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    pub fn get_command_audit_option(
        &mut self,
        command: CommandCode,
    ) -> Result<AuditOption, ClientError> {
        let command_audit_options = self.get_commands_audit_options()?;
        Ok(command_audit_options
            .iter()
            .find(|opt| opt.command_type() == command)
            .map(|opt| opt.audit_option())
            .unwrap_or(AuditOption::Off))
    }

    /// Get the audit policy settings for all commands.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    pub fn get_commands_audit_options(&mut self) -> Result<Vec<AuditCommand>, ClientError> {
        let response = self.send_command(GetOptionCommand {
            tag: AuditTag::Command,
        })?;

        Ok(deserialize(&response.0)?)
    }

    /// Get the forced auditing global option: when enabled, the device will
    /// refuse operations if the [log store] becomes full.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
    /// [log store]: https://developers.yubico.com/YubiHSM2/Concepts/Logs.html
    pub fn get_force_audit_option(&mut self) -> Result<AuditOption, ClientError> {
        let response = self.send_command(GetOptionCommand {
            tag: AuditTag::Force,
        })?;

        ensure!(
            response.0.len() == 1,
            ProtocolError,
            "expected 1-byte response, got {}",
            response.0.len()
        );

        AuditOption::from_u8(response.0[0]).map_err(|e| err!(ProtocolError, e))
    }

    /// Get some number of bytes of pseudo random data generated on the device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html>
    pub fn get_pseudo_random(&mut self, bytes: usize) -> Result<Vec<u8>, ClientError> {
        ensure!(
            bytes <= MAX_RAND_BYTES,
            ProtocolError,
            "requested number of bytes too large: {} (max: {})",
            bytes,
            MAX_RAND_BYTES
        );

        Ok(self
            .send_command(GetPseudoRandomCommand {
                bytes: bytes as u16,
            })?.bytes)
    }

    /// Get the public key for an asymmetric key stored on the device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html>
    pub fn get_pubkey(&mut self, key_id: ObjectId) -> Result<PublicKey, ClientError> {
        Ok(self.send_command(GetPubKeyCommand { key_id })?)
    }

    /// Compute an HMAC tag of the given data with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Hmac_Data.html>
    pub fn hmac<M>(&mut self, key_id: ObjectId, msg: M) -> Result<HMACTag, ClientError>
    where
        M: Into<Vec<u8>>,
    {
        Ok(self.send_command(HMACDataCommand {
            key_id,
            data: msg.into(),
        })?)
    }

    /// Import an encrypted object from the HSM using the given key-wrapping key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Import_Wrapped.html>
    pub fn import_wrapped<M>(
        &mut self,
        wrap_key_id: ObjectId,
        wrap_message: M,
    ) -> Result<ImportWrappedResponse, ClientError>
    where
        M: Into<WrapMessage>,
    {
        let WrapMessage { nonce, ciphertext } = wrap_message.into();

        Ok(self.send_command(ImportWrappedCommand {
            wrap_key_id,
            nonce,
            ciphertext,
        })?)
    }

    /// List objects visible from the current session.
    ///
    /// Optionally apply a set of provided `filters` which select objects
    /// based on their attributes.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
    pub fn list_objects(
        &mut self,
        filters: &[Filter],
    ) -> Result<Vec<ListObjectsEntry>, ClientError> {
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
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: AsymmetricAlg,
        key_bytes: K,
    ) -> Result<ObjectId, ClientError>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutAsymmetricKeyCommand {
                params: PutObjectParams {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data,
            })?.key_id)
    }

    /// Put an existing `AuthKey` into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Authkey.html>
    // TODO: use clippy's scoped lints once they work on stable
    #[allow(unknown_lints, renamed_and_removed_lints, too_many_arguments)]
    pub fn put_auth_key<K>(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: AuthAlg,
        auth_key: K,
    ) -> Result<ObjectId, ClientError>
    where
        K: Into<AuthKey>,
    {
        Ok(self
            .send_command(PutAuthKeyCommand {
                params: PutObjectParams {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
                auth_key: auth_key.into(),
            })?.key_id)
    }

    /// Put an existing HMAC key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Hmac_Key.html>
    pub fn put_hmac_key<K>(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: HmacAlg,
        key_bytes: K,
    ) -> Result<ObjectId, ClientError>
    where
        K: Into<Vec<u8>>,
    {
        let hmac_key = key_bytes.into();

        if hmac_key.len() < HMAC_MIN_KEY_SIZE || hmac_key.len() > algorithm.max_key_len() {
            fail!(
                ProtocolError,
                "invalid key length for {:?}: {} (min {}, max {})",
                algorithm,
                hmac_key.len(),
                HMAC_MIN_KEY_SIZE,
                algorithm.max_key_len()
            );
        }

        Ok(self
            .send_command(PutHMACKeyCommand {
                params: PutObjectParams {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                hmac_key,
            })?.key_id)
    }

    /// Put an opaque object (X.509 certificate or other bytestring) into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Opaque.html>
    pub fn put_opaque<B>(
        &mut self,
        object_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: OpaqueAlg,
        opaque_data: B,
    ) -> Result<ObjectId, ClientError>
    where
        B: Into<Vec<u8>>,
    {
        Ok(self
            .send_command(PutOpaqueCommand {
                params: PutObjectParams {
                    id: object_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data: opaque_data.into(),
            })?.object_id)
    }

    /// Configure the audit policy settings for a particular command, e.g. auditing
    /// should be `On`, `Off`, or `Fix` (i.e. fixed permanently on).
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>
    pub fn put_command_audit_option(
        &mut self,
        command: CommandCode,
        audit_option: AuditOption,
    ) -> Result<(), ClientError> {
        self.send_command(PutOptionCommand {
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
    /// [log store]: https://developers.yubico.com/YubiHSM2/Concepts/Logs.html
    pub fn put_force_audit_option(&mut self, option: AuditOption) -> Result<(), ClientError> {
        self.send_command(PutOptionCommand {
            tag: AuditTag::Force,
            length: 1,
            value: vec![option.to_u8()],
        })?;

        Ok(())
    }

    /// Put an existing OTP AEAD key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Otp_Aead_Key.html>
    pub fn put_otp_aead_key<K>(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        algorithm: OtpAlg,
        key_bytes: K,
    ) -> Result<ObjectId, ClientError>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutOTPAEADKeyCommand {
                params: PutObjectParams {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                data,
            })?.key_id)
    }

    /// Put an existing wrap key into the HSM.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Put_Wrap_Key.html>
    // TODO: use clippy's scoped lints once they work on stable
    #[allow(unknown_lints, renamed_and_removed_lints, too_many_arguments)]
    pub fn put_wrap_key<K>(
        &mut self,
        key_id: ObjectId,
        label: ObjectLabel,
        domains: Domain,
        capabilities: Capability,
        delegated_capabilities: Capability,
        algorithm: WrapAlg,
        key_bytes: K,
    ) -> Result<ObjectId, ClientError>
    where
        K: Into<Vec<u8>>,
    {
        let data = key_bytes.into();

        if data.len() != algorithm.key_len() {
            fail!(
                ProtocolError,
                "invalid key length for {:?}: {} (expected {})",
                algorithm,
                data.len(),
                algorithm.key_len()
            );
        }

        Ok(self
            .send_command(PutWrapKeyCommand {
                params: PutObjectParams {
                    id: key_id,
                    label,
                    domains,
                    capabilities,
                    algorithm: algorithm.into(),
                },
                delegated_capabilities,
                data,
            })?.key_id)
    }

    /// Reset the HSM to a factory default state and reboot, clearing all
    /// stored objects and restoring the default auth key.
    ///
    /// **WARNING:** This wipes all keys and other data from the HSM! Make
    /// absolutely sure you want to use this!
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Reset.html>
    pub fn reset(&mut self) -> Result<(), ClientError> {
        // TODO: handle potential errors that occur when resetting
        if let Err(e) = self.send_command(ResetCommand {}) {
            debug!("error sending reset command: {}", e);
        }

        // Resetting the HSM invalidates our session
        self.session = None;
        Ok(())
    }

    /// Set the index of the last consumed index of the HSM audit log.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Set_Log_Index.html>
    pub fn set_log_index(&mut self, log_index: u16) -> Result<(), ClientError> {
        self.send_command(SetLogIndexCommand { log_index })?;
        Ok(())
    }

    /// Compute an ECDSA signature of the given digest (i.e. a precomputed SHA-2 digest)
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Ecdsa.html>
    ///
    /// # secp256k1 notes
    ///
    /// The YubiHSM2 does not produce signatures in "low S" form, which is expected
    /// for most cryptocurrency applications (the typical use case for secp256k1).
    ///
    /// If your application demands this (e.g. Bitcoin), you'll need to normalize
    /// the signatures. One option for this is the `secp256k1` crate's
    /// [Signature::normalize_s] function.
    ///
    /// The [signatory-yubihsm] crate automatically normalizes secp256k1 ECDSA
    /// signatures to "low S" form. Consider using that if you'd like a ready-made
    /// solution for cryptocurrency applications.
    ///
    /// [Signature::normalize_s]: https://docs.rs/secp256k1/latest/secp256k1/struct.Signature.html#method.normalize_s
    /// [signatory-yubihsm]: https://docs.rs/signatory-yubihsm/latest/signatory_yubihsm/ecdsa/struct.ECDSASigner.html
    pub fn sign_ecdsa<T>(
        &mut self,
        key_id: ObjectId,
        digest: T,
    ) -> Result<ECDSASignature, ClientError>
    where
        T: Into<Vec<u8>>,
    {
        Ok(self.send_command(SignDataECDSACommand {
            key_id,
            digest: digest.into(),
        })?)
    }

    /// Compute an Ed25519 signature with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Eddsa.html>
    pub fn sign_ed25519<T>(
        &mut self,
        key_id: ObjectId,
        data: T,
    ) -> Result<Ed25519Signature, ClientError>
    where
        T: Into<Vec<u8>>,
    {
        Ok(self.send_command(SignDataEdDSACommand {
            key_id,
            data: data.into(),
        })?)
    }

    /// Compute an RSASSA-PKCS#1v1.5 signature of the SHA-256 hash of the given data.
    ///
    /// **WARNING**: This method has not been tested and is not confirmed to actually work! Use at your
    /// own risk!
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Pkcs1.html>
    #[cfg(feature = "rsa")]
    pub fn sign_rsa_pkcs1v15_sha256(
        &mut self,
        key_id: ObjectId,
        data: &[u8],
    ) -> Result<RSAPKCS1Signature, ClientError> {
        Ok(self.send_command(SignDataPKCS1Command {
            key_id,
            digest: Sha256::digest(data).as_slice().into(),
        })?)
    }

    /// Compute an RSASSA-PSS signature of the SHA-256 hash of the given data with the given key ID.
    ///
    /// **WARNING**: This method has not been tested and is not confirmed to actually work! Use at your
    /// own risk!
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Pss.html>
    #[cfg(feature = "rsa")]
    pub fn sign_rsa_pss_sha256(
        &mut self,
        key_id: ObjectId,
        data: &[u8],
    ) -> Result<RSAPSSSignature, ClientError> {
        ensure!(
            data.len() > RSA_PSS_MAX_MESSAGE_SIZE,
            ProtocolError,
            "message too large to be signed (max: {})",
            RSA_PSS_MAX_MESSAGE_SIZE
        );

        let mut hasher = Sha256::default();

        let mut length = [0u8; 2];
        BigEndian::write_u16(&mut length, data.len() as u16);
        hasher.input(&length);
        hasher.input(data);
        let digest = hasher.result();

        Ok(self.send_command(SignDataPSSCommand {
            key_id,
            mgf1_hash_alg: Algorithm::Mgf(MgfAlg::SHA256),
            salt_len: digest.as_slice().len() as u16,
            digest: digest.as_slice().into(),
        })?)
    }

    /// Get storage status (i.e. currently free storage) from the HSM device.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Storage_Status.html>
    pub fn storage_status(&mut self) -> Result<StorageStatusResponse, ClientError> {
        Ok(self.send_command(StorageStatusCommand {})?)
    }

    /// Decrypt data which was encrypted (using AES-CCM) under a wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Unwrap_Data.html>
    pub fn unwrap_data<M>(
        &mut self,
        wrap_key_id: ObjectId,
        wrap_message: M,
    ) -> Result<Vec<u8>, ClientError>
    where
        M: Into<WrapMessage>,
    {
        let WrapMessage { nonce, ciphertext } = wrap_message.into();

        Ok(self
            .send_command(UnwrapDataCommand {
                wrap_key_id,
                nonce,
                ciphertext,
            })?.0)
    }

    /// Verify an HMAC tag of the given data with the given key ID.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Verify_Hmac.html>
    pub fn verify_hmac<M, T>(&mut self, key_id: ObjectId, msg: M, tag: T) -> Result<(), ClientError>
    where
        M: Into<Vec<u8>>,
        T: Into<HMACTag>,
    {
        let result = self.send_command(VerifyHMACCommand {
            key_id,
            tag: tag.into(),
            data: msg.into(),
        })?;

        if result.0 == 1 {
            Ok(())
        } else {
            Err(err!(ResponseError, "HMAC verification failure"))
        }
    }

    /// Encrypt data (with AES-CCM) using the given wrap key.
    ///
    /// <https://developers.yubico.com/YubiHSM2/Commands/Wrap_Data.html>
    pub fn wrap_data(
        &mut self,
        wrap_key_id: ObjectId,
        plaintext: Vec<u8>,
    ) -> Result<WrapMessage, ClientError> {
        Ok(self
            .send_command(WrapDataCommand {
                wrap_key_id,
                plaintext,
            })?.0)
    }
}
