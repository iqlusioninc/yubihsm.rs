//! Commands supported by the `MockHSM`

use hmac::{Hmac, Mac};
use rand::{OsRng, RngCore};
use ring::signature::Ed25519KeyPair;
use sha2::Sha256;
use untrusted;

use adapters::AdapterError;
use algorithm::*;
use audit::{AuditCommand, AuditOption, AuditTag};
use commands::{
    blink::BlinkResponse,
    close_session::CloseSessionResponse,
    create_session::{CreateSessionCommand, CreateSessionResponse},
    delete_object::{DeleteObjectCommand, DeleteObjectResponse},
    device_info::DeviceInfoResponse,
    echo::EchoResponse,
    export_wrapped::{ExportWrappedCommand, ExportWrappedResponse},
    generate_asymmetric_key::{GenAsymmetricKeyCommand, GenAsymmetricKeyResponse},
    generate_hmac_key::{GenHMACKeyCommand, GenHMACKeyResponse},
    generate_wrap_key::{GenWrapKeyCommand, GenWrapKeyResponse},
    get_logs::AuditLogs,
    get_object_info::{GetObjectInfoCommand, GetObjectInfoResponse},
    get_opaque::{GetOpaqueCommand, GetOpaqueResponse},
    get_option::{GetOptionCommand, GetOptionResponse},
    get_pseudo_random::{GetPseudoRandomCommand, GetPseudoRandomResponse},
    get_pubkey::{GetPubKeyCommand, PublicKey},
    hmac::{HMACDataCommand, HMACTag},
    import_wrapped::{ImportWrappedCommand, ImportWrappedResponse},
    list_objects::{ListObjectsCommand, ListObjectsEntry, ListObjectsResponse},
    put_asymmetric_key::{PutAsymmetricKeyCommand, PutAsymmetricKeyResponse},
    put_auth_key::{PutAuthKeyCommand, PutAuthKeyResponse},
    put_hmac_key::{PutHMACKeyCommand, PutHMACKeyResponse},
    put_opaque::{PutOpaqueCommand, PutOpaqueResponse},
    put_option::{PutOptionCommand, PutOptionResponse},
    put_wrap_key::{PutWrapKeyCommand, PutWrapKeyResponse},
    reset::ResetResponse,
    set_log_index::SetLogIndexResponse,
    sign_ecdsa::{ECDSASignature, SignDataECDSACommand},
    sign_eddsa::{Ed25519Signature, SignDataEdDSACommand, ED25519_SIGNATURE_SIZE},
    storage_status::StorageStatusResponse,
    verify_hmac::{VerifyHMACCommand, VerifyHMACResponse},
    CommandType, Response,
};
use error::HsmErrorKind;
use securechannel::{CommandMessage, ResponseMessage};
use serializers::deserialize;
use {Capability, ObjectType, SessionId, WrapMessage, WrapNonce};

use super::objects::Payload;
use super::state::State;

/// Create a new HSM session
pub(crate) fn create_session(
    state: &mut State,
    cmd_message: &CommandMessage,
) -> Result<Vec<u8>, AdapterError> {
    let cmd: CreateSessionCommand = deserialize(cmd_message.data.as_ref())
        .unwrap_or_else(|e| panic!("error parsing CreateSession command data: {:?}", e));

    let session = state.create_session(cmd.auth_key_id, cmd.host_challenge);

    let mut response = CreateSessionResponse {
        card_challenge: *session.card_challenge(),
        card_cryptogram: session.card_cryptogram(),
    }.serialize();

    response.session_id = Some(session.id);
    Ok(response.into())
}

/// Authenticate an HSM session
pub(crate) fn authenticate_session(
    state: &mut State,
    command: &CommandMessage,
) -> Result<Vec<u8>, AdapterError> {
    let session_id = command
        .session_id
        .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

    Ok(state
        .get_session(session_id)?
        .channel
        .verify_authenticate_session(command)
        .unwrap()
        .into())
}

/// Encrypted session messages
pub(crate) fn session_message(
    state: &mut State,
    encrypted_command: CommandMessage,
) -> Result<Vec<u8>, AdapterError> {
    let session_id = encrypted_command.session_id.unwrap_or_else(|| {
        panic!(
            "no session ID in command: {:?}",
            encrypted_command.command_type
        )
    });

    let command = state
        .get_session(session_id)?
        .decrypt_command(encrypted_command);

    let response = match command.command_type {
        CommandType::Blink => BlinkResponse {}.serialize(),
        CommandType::CloseSession => return close_session(state, session_id),
        CommandType::DeleteObject => delete_object(state, &command.data),
        CommandType::DeviceInfo => device_info(),
        CommandType::Echo => echo(&command.data),
        CommandType::ExportWrapped => export_wrapped(state, &command.data),
        CommandType::GenerateAsymmetricKey => gen_asymmetric_key(state, &command.data),
        CommandType::GenerateHMACKey => gen_hmac_key(state, &command.data),
        CommandType::GenerateWrapKey => gen_wrap_key(state, &command.data),
        CommandType::GetLogs => get_logs(),
        CommandType::GetObjectInfo => get_object_info(state, &command.data),
        CommandType::GetOpaqueObject => get_opaque(state, &command.data),
        CommandType::GetOption => get_option(state, &command.data),
        CommandType::GetPseudoRandom => get_pseudo_random(state, &command.data),
        CommandType::GetPubKey => get_pubkey(state, &command.data),
        CommandType::HMACData => hmac_data(state, &command.data),
        CommandType::ImportWrapped => import_wrapped(state, &command.data),
        CommandType::ListObjects => list_objects(state, &command.data),
        CommandType::PutAsymmetricKey => put_asymmetric_key(state, &command.data),
        CommandType::PutAuthKey => put_auth_key(state, &command.data),
        CommandType::PutHMACKey => put_hmac_key(state, &command.data),
        CommandType::PutOpaqueObject => put_opaque(state, &command.data),
        CommandType::PutOption => put_option(state, &command.data),
        CommandType::PutWrapKey => put_wrap_key(state, &command.data),
        CommandType::Reset => return Ok(reset(state, session_id)),
        CommandType::SetLogIndex => SetLogIndexResponse {}.serialize(),
        CommandType::SignDataECDSA => sign_data_ecdsa(state, &command.data),
        CommandType::SignDataEdDSA => sign_data_eddsa(state, &command.data),
        CommandType::StorageStatus => storage_status(),
        CommandType::VerifyHMAC => verify_hmac(state, &command.data),
        unsupported => panic!("unsupported command type: {:?}", unsupported),
    };

    Ok(state
        .get_session(session_id)?
        .encrypt_response(response)
        .into())
}

/// Close an active session
fn close_session(state: &mut State, session_id: SessionId) -> Result<Vec<u8>, AdapterError> {
    let response = state
        .get_session(session_id)?
        .encrypt_response(CloseSessionResponse {}.serialize());

    state.close_session(session_id);
    Ok(response.into())
}

/// Delete an object
fn delete_object(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let command: DeleteObjectCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::DeleteObject: {:?}", e));

    if state
        .objects
        .remove(command.object_id, command.object_type)
        .is_some()
    {
        DeleteObjectResponse {}.serialize()
    } else {
        debug!("no such object ID: {:?}", command.object_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Generate a mock device information report
fn device_info() -> ResponseMessage {
    DeviceInfoResponse {
        major_version: 2,
        minor_version: 0,
        build_version: 0,
        serial_number: 2_000_000,
        log_store_capacity: 62,
        log_store_used: 62,
        algorithms: vec![
            Algorithm::Rsa(RsaAlg::PKCS1_SHA1),
            Algorithm::Rsa(RsaAlg::PKCS1_SHA256),
            Algorithm::Rsa(RsaAlg::PKCS1_SHA384),
            Algorithm::Rsa(RsaAlg::PKCS1_SHA512),
            Algorithm::Rsa(RsaAlg::PSS_SHA1),
            Algorithm::Rsa(RsaAlg::PSS_SHA256),
            Algorithm::Rsa(RsaAlg::PSS_SHA384),
            Algorithm::Rsa(RsaAlg::PSS_SHA512),
            Algorithm::Asymmetric(AsymmetricAlg::RSA_2048),
            Algorithm::Asymmetric(AsymmetricAlg::RSA_3072),
            Algorithm::Asymmetric(AsymmetricAlg::RSA_4096),
            Algorithm::Asymmetric(AsymmetricAlg::EC_P256),
            Algorithm::Asymmetric(AsymmetricAlg::EC_P384),
            Algorithm::Asymmetric(AsymmetricAlg::EC_P521),
            Algorithm::Asymmetric(AsymmetricAlg::EC_K256),
            Algorithm::Asymmetric(AsymmetricAlg::EC_BP256),
            Algorithm::Asymmetric(AsymmetricAlg::EC_BP384),
            Algorithm::Asymmetric(AsymmetricAlg::EC_BP512),
            Algorithm::Hmac(HmacAlg::SHA1),
            Algorithm::Hmac(HmacAlg::SHA256),
            Algorithm::Hmac(HmacAlg::SHA384),
            Algorithm::Hmac(HmacAlg::SHA512),
            Algorithm::Ecdsa(EcdsaAlg::SHA1),
            Algorithm::Kex(KexAlg::ECDH),
            Algorithm::Rsa(RsaAlg::OAEP_SHA1),
            Algorithm::Rsa(RsaAlg::OAEP_SHA256),
            Algorithm::Rsa(RsaAlg::OAEP_SHA384),
            Algorithm::Rsa(RsaAlg::OAEP_SHA512),
            Algorithm::Wrap(WrapAlg::AES128_CCM),
            Algorithm::Opaque(OpaqueAlg::DATA),
            Algorithm::Opaque(OpaqueAlg::X509_CERT),
            Algorithm::Mgf(MgfAlg::SHA1),
            Algorithm::Mgf(MgfAlg::SHA256),
            Algorithm::Mgf(MgfAlg::SHA384),
            Algorithm::Mgf(MgfAlg::SHA512),
            Algorithm::Template(TemplateAlg::SSH),
            Algorithm::Otp(OtpAlg::AES128),
            Algorithm::Auth(AuthAlg::YUBICO_AES),
            Algorithm::Otp(OtpAlg::AES192),
            Algorithm::Otp(OtpAlg::AES256),
            Algorithm::Wrap(WrapAlg::AES192_CCM),
            Algorithm::Wrap(WrapAlg::AES256_CCM),
            Algorithm::Ecdsa(EcdsaAlg::SHA256),
            Algorithm::Ecdsa(EcdsaAlg::SHA384),
            Algorithm::Ecdsa(EcdsaAlg::SHA512),
            Algorithm::Asymmetric(AsymmetricAlg::Ed25519),
            Algorithm::Asymmetric(AsymmetricAlg::EC_P224),
        ],
    }.serialize()
}

/// Echo a message back to the host
fn echo(cmd_data: &[u8]) -> ResponseMessage {
    EchoResponse(cmd_data.into()).serialize()
}

/// Export an object from the HSM in encrypted form
fn export_wrapped(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let ExportWrappedCommand {
        wrap_key_id,
        object_type,
        object_id,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::ExportWrapped: {:?}", e));

    let nonce = WrapNonce::generate();

    match state
        .objects
        .wrap(wrap_key_id, object_id, object_type, &nonce)
    {
        Ok(ciphertext) => ExportWrappedResponse(WrapMessage { nonce, ciphertext }).serialize(),
        Err(e) => {
            debug!("error wrapping object: {}", e);
            HsmErrorKind::CommandInvalid.into()
        }
    }
}

/// Generate a new random asymmetric key
fn gen_asymmetric_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let GenAsymmetricKeyCommand(command) = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GenAsymmetricKey: {:?}", e));

    state.objects.generate(
        command.key_id,
        ObjectType::AsymmetricKey,
        command.algorithm,
        command.label,
        command.capabilities,
        Capability::default(),
        command.domains,
    );

    GenAsymmetricKeyResponse {
        key_id: command.key_id,
    }.serialize()
}

/// Generate a new random HMAC key
fn gen_hmac_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let GenHMACKeyCommand(command) = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GenHMACKey: {:?}", e));

    state.objects.generate(
        command.key_id,
        ObjectType::HMACKey,
        command.algorithm,
        command.label,
        command.capabilities,
        Capability::default(),
        command.domains,
    );

    GenHMACKeyResponse {
        key_id: command.key_id,
    }.serialize()
}

/// Generate a new random wrap (i.e. AES-CCM) key
fn gen_wrap_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let GenWrapKeyCommand {
        params,
        delegated_capabilities,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GenWrapKey: {:?}", e));

    state.objects.generate(
        params.key_id,
        ObjectType::WrapKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
    );

    GenWrapKeyResponse {
        key_id: params.key_id,
    }.serialize()
}

/// Get mock log information
fn get_logs() -> ResponseMessage {
    // TODO: mimic the YubiHSM's actual audit log
    AuditLogs {
        unlogged_boot_events: 0,
        unlogged_auth_events: 0,
        num_entries: 0,
        entries: vec![],
    }.serialize()
}

/// Get detailed info about a specific object
fn get_object_info(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetObjectInfoCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetObjectInfo: {:?}", e));

    if let Some(obj) = state
        .objects
        .get(command.0.object_id, command.0.object_type)
    {
        GetObjectInfoResponse(obj.object_info.clone()).serialize()
    } else {
        debug!("no such object ID: {:?}", command.0.object_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Get an opaque object (X.509 certificate or other data) stored in the HSM
fn get_opaque(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetOpaqueCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetOpaqueObject: {:?}", e));

    if let Some(obj) = state.objects.get(command.object_id, ObjectType::Opaque) {
        GetOpaqueResponse(obj.payload.as_ref().into()).serialize()
    } else {
        debug!("no such opaque object ID: {:?}", command.object_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Get an auditing option
fn get_option(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetOptionCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetOpaqueObject: {:?}", e));

    let results = match command.tag {
        AuditTag::Command => state.command_audit_options.serialize(),
        AuditTag::Force => vec![state.force_audit.to_u8()],
    };

    GetOptionResponse(results).serialize()
}

/// Get bytes of random data
fn get_pseudo_random(_state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetPseudoRandomCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetPseudoRandom: {:?}", e));

    let mut rng = OsRng::new().unwrap();
    let mut bytes = vec![0u8; command.bytes as usize];
    rng.fill_bytes(&mut bytes[..]);

    GetPseudoRandomResponse { bytes }.serialize()
}

/// Get the public key associated with a key in the HSM
fn get_pubkey(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetPubKeyCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetPubKey: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::AsymmetricKey) {
        PublicKey {
            algorithm: obj.algorithm().asymmetric().unwrap(),
            bytes: obj.payload.public_key_bytes().unwrap(),
        }.serialize()
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Compute the HMAC tag for the given data
fn hmac_data(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: HMACDataCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::HMACData: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::HMACKey) {
        if let Payload::HmacKey(alg, ref key) = obj.payload {
            assert_eq!(alg, HmacAlg::SHA256);
            let mut mac = Hmac::<Sha256>::new_varkey(key).unwrap();
            mac.input(&command.data);
            let tag = mac.result();
            HMACTag(tag.code().as_ref().into()).serialize()
        } else {
            debug!("not an HMAC key: {:?}", obj.algorithm());
            HsmErrorKind::CommandInvalid.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Import an object encrypted under a wrap key into the HSM
fn import_wrapped(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let ImportWrappedCommand {
        wrap_key_id,
        nonce,
        ciphertext,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::ImportWrapped: {:?}", e));

    match state.objects.unwrap(wrap_key_id, &nonce, ciphertext) {
        Ok(obj) => ImportWrappedResponse {
            object_type: obj.object_type,
            object_id: obj.object_id,
        }.serialize(),
        Err(e) => {
            debug!("error unwrapping object: {}", e);
            HsmErrorKind::CommandInvalid.into()
        }
    }
}

/// List all objects presently accessible to a session
fn list_objects(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    // TODO: filter support
    let _command: ListObjectsCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::ListObjects: {:?}", e));

    let list_entries = state
        .objects
        .iter()
        .map(|(_, object)| ListObjectsEntry {
            object_id: object.object_info.object_id,
            object_type: object.object_info.object_type,
            sequence: object.object_info.sequence,
        }).collect();

    ListObjectsResponse(list_entries).serialize()
}

/// Put an existing asymmetric key into the HSM
fn put_asymmetric_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutAsymmetricKeyCommand { params, data } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutAsymmetricKey: {:?}", e));

    state.objects.put(
        params.id,
        ObjectType::AsymmetricKey,
        params.algorithm,
        params.label,
        params.capabilities,
        Capability::default(),
        params.domains,
        &data,
    );

    PutAsymmetricKeyResponse { key_id: params.id }.serialize()
}

/// Put a new authentication key into the HSM
fn put_auth_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutAuthKeyCommand {
        params,
        delegated_capabilities,
        auth_key,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutAuthKey: {:?}", e));

    state.objects.put(
        params.id,
        ObjectType::AuthKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
        &auth_key.0,
    );

    PutAuthKeyResponse { key_id: params.id }.serialize()
}

/// Put a new HMAC key into the HSM
fn put_hmac_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutHMACKeyCommand { params, hmac_key } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutHMACKey: {:?}", e));

    state.objects.put(
        params.id,
        ObjectType::HMACKey,
        params.algorithm,
        params.label,
        params.capabilities,
        Capability::default(),
        params.domains,
        &hmac_key,
    );

    PutHMACKeyResponse { key_id: params.id }.serialize()
}

/// Put an opaque object (X.509 cert or other data) into the HSM
fn put_opaque(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutOpaqueCommand { params, data } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutOpaqueObject: {:?}", e));

    state.objects.put(
        params.id,
        ObjectType::Opaque,
        params.algorithm,
        params.label,
        params.capabilities,
        Capability::default(),
        params.domains,
        &data,
    );

    PutOpaqueResponse {
        object_id: params.id,
    }.serialize()
}

/// Change an HSM auditing setting
fn put_option(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutOptionCommand { tag, length, value } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutOption: {:?}", e));

    match tag {
        AuditTag::Force => {
            assert_eq!(length, 1);
            state.force_audit = AuditOption::from_u8(value[0]).unwrap()
        }
        AuditTag::Command => {
            assert_eq!(length, 2);
            let audit_cmd: AuditCommand = deserialize(&value)
                .unwrap_or_else(|e| panic!("error parsing AuditCommand: {:?}", e));

            state
                .command_audit_options
                .put(audit_cmd.command_type(), audit_cmd.audit_option());
        }
    }

    PutOptionResponse {}.serialize()
}

/// Put an existing wrap (i.e. AES-CCM) key into the HSM
fn put_wrap_key(state: &mut State, cmd_data: &[u8]) -> ResponseMessage {
    let PutWrapKeyCommand {
        params,
        delegated_capabilities,
        data,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::PutWrapKey: {:?}", e));

    state.objects.put(
        params.id,
        ObjectType::WrapKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
        &data,
    );

    PutWrapKeyResponse { key_id: params.id }.serialize()
}

/// Reset the MockHSM back to its default state
fn reset(state: &mut State, session_id: SessionId) -> Vec<u8> {
    let response = state
        .get_session(session_id)
        .unwrap()
        .encrypt_response(ResetResponse(0x01).serialize())
        .into();

    state.reset();
    response
}

/// Sign a message using the ECDSA signature algorithm
fn sign_data_ecdsa(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: SignDataECDSACommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::SignDataEdDSA: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::AsymmetricKey) {
        if let Payload::EcdsaKeyPair(ref key) = obj.payload {
            ECDSASignature(key.sign(command.digest).as_ref().into()).serialize()
        } else {
            debug!("not an ECDSA key: {:?}", obj.algorithm());
            HsmErrorKind::CommandInvalid.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Sign a message using the Ed25519 signature algorithm
fn sign_data_eddsa(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: SignDataEdDSACommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::SignDataEdDSA: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::AsymmetricKey) {
        if let Payload::Ed25519KeyPair(ref seed) = obj.payload {
            let keypair =
                Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed)).unwrap();

            let mut signature_bytes = [0u8; ED25519_SIGNATURE_SIZE];
            signature_bytes.copy_from_slice(keypair.sign(command.data.as_ref()).as_ref());

            Ed25519Signature(signature_bytes).serialize()
        } else {
            debug!("not an Ed25519 key: {:?}", obj.algorithm());
            HsmErrorKind::CommandInvalid.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}

/// Generate a mock storage status report
fn storage_status() -> ResponseMessage {
    // TODO: model actual free storage
    StorageStatusResponse {
        total_records: 256,
        free_records: 256,
        total_pages: 1024,
        free_pages: 1024,
        page_size: 126,
    }.serialize()
}

/// Verify the HMAC tag for the given data
fn verify_hmac(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: VerifyHMACCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::HMACData: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::HMACKey) {
        if let Payload::HmacKey(alg, ref key) = obj.payload {
            assert_eq!(alg, HmacAlg::SHA256);

            // Because of a quirk of our serde parser everything winds up in the tag field
            let data = command.tag.into_vec();

            let mut mac = Hmac::<Sha256>::new_varkey(key).unwrap();
            mac.input(&data[32..]);
            let tag = mac.result();
            let is_ok = tag.is_equal(&data[..32]);

            VerifyHMACResponse(is_ok as u8).serialize()
        } else {
            debug!("not an HMAC key: {:?}", obj.algorithm());
            HsmErrorKind::CommandInvalid.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        HsmErrorKind::ObjectNotFound.into()
    }
}
