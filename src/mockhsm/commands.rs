//! Commands supported by the `MockHSM`

use rand::{OsRng, RngCore};
use ring::signature::Ed25519KeyPair;
use untrusted;

use commands::{
    blink::BlinkResponse,
    close_session::CloseSessionResponse,
    create_session::{CreateSessionCommand, CreateSessionResponse},
    delete_object::{DeleteObjectCommand, DeleteObjectResponse},
    device_info::DeviceInfoResponse,
    echo::EchoResponse,
    export_wrapped::{ExportWrappedCommand, ExportWrappedResponse},
    generate_asymmetric_key::{GenAsymmetricKeyCommand, GenAsymmetricKeyResponse},
    generate_wrap_key::{GenWrapKeyCommand, GenWrapKeyResponse},
    get_logs::GetLogsResponse,
    get_object_info::{GetObjectInfoCommand, GetObjectInfoResponse},
    get_opaque::{GetOpaqueCommand, GetOpaqueResponse},
    get_pseudo_random::{GetPseudoRandomCommand, GetPseudoRandomResponse},
    get_pubkey::{GetPubKeyCommand, PublicKey},
    import_wrapped::{ImportWrappedCommand, ImportWrappedResponse},
    list_objects::{ListObjectsCommand, ListObjectsEntry, ListObjectsResponse},
    put_asymmetric_key::{PutAsymmetricKeyCommand, PutAsymmetricKeyResponse},
    put_opaque::{PutOpaqueCommand, PutOpaqueResponse},
    put_wrap_key::{PutWrapKeyCommand, PutWrapKeyResponse},
    reset::ResetResponse,
    sign_ecdsa::{ECDSASignature, SignDataECDSACommand},
    sign_eddsa::{ED25519_SIGNATURE_SIZE, Ed25519Signature, SignDataEdDSACommand},
    storage_status::StorageStatusResponse,
    CommandType, Response,
};
use connector::ConnectorError;
use securechannel::{CommandMessage, ResponseMessage};
use serializers::deserialize;
use {Algorithm, AsymmetricAlgorithm, Capability, ObjectId, ObjectType, SessionId, WrapNonce};

use super::objects::Payload;
use super::state::State;

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Create a new HSM session
pub(crate) fn create_session(
    state: &mut State,
    cmd_message: &CommandMessage,
) -> Result<Vec<u8>, ConnectorError> {
    let cmd: CreateSessionCommand = deserialize(cmd_message.data.as_ref())
        .unwrap_or_else(|e| panic!("error parsing CreateSession command data: {:?}", e));

    assert_eq!(
        cmd.auth_key_id, DEFAULT_AUTH_KEY_ID,
        "unexpected auth key ID: {}",
        cmd.auth_key_id
    );

    let session = state.create_session(cmd.host_challenge);

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
) -> Result<Vec<u8>, ConnectorError> {
    let session_id = command
        .session_id
        .unwrap_or_else(|| panic!("no session ID in command: {:?}", command.command_type));

    Ok(state
        .get_session(session_id)
        .channel
        .verify_authenticate_session(command)
        .unwrap()
        .into())
}

/// Encrypted session messages
pub(crate) fn session_message(
    state: &mut State,
    encrypted_command: CommandMessage,
) -> Result<Vec<u8>, ConnectorError> {
    let session_id = encrypted_command.session_id.unwrap_or_else(|| {
        panic!(
            "no session ID in command: {:?}",
            encrypted_command.command_type
        )
    });

    let command = state
        .get_session(session_id)
        .decrypt_command(encrypted_command);

    let response = match command.command_type {
        CommandType::Blink => BlinkResponse {}.serialize(),
        CommandType::CloseSession => return Ok(close_session(state, session_id)),
        CommandType::DeleteObject => delete_object(state, &command.data),
        CommandType::DeviceInfo => device_info(),
        CommandType::Echo => echo(&command.data),
        CommandType::ExportWrapped => export_wrapped(state, &command.data),
        CommandType::GenerateAsymmetricKey => gen_asymmetric_key(state, &command.data),
        CommandType::GenerateWrapKey => gen_wrap_key(state, &command.data),
        CommandType::GetLogs => get_logs(),
        CommandType::GetObjectInfo => get_object_info(state, &command.data),
        CommandType::GetOpaqueObject => get_opaque(state, &command.data),
        CommandType::GetPseudoRandom => get_pseudo_random(state, &command.data),
        CommandType::GetPubKey => get_pubkey(state, &command.data),
        CommandType::ImportWrapped => import_wrapped(state, &command.data),
        CommandType::ListObjects => list_objects(state, &command.data),
        CommandType::PutAsymmetricKey => put_asymmetric_key(state, &command.data),
        CommandType::PutOpaqueObject => put_opaque(state, &command.data),
        CommandType::PutWrapKey => put_wrap_key(state, &command.data),
        CommandType::Reset => ResetResponse(0x01).serialize(),
        CommandType::SignDataECDSA => sign_data_ecdsa(state, &command.data),
        CommandType::SignDataEdDSA => sign_data_eddsa(state, &command.data),
        CommandType::StorageStatus => storage_status(),
        unsupported => panic!("unsupported command type: {:?}", unsupported),
    };

    Ok(state
        .get_session(session_id)
        .encrypt_response(response)
        .into())
}

/// Close an active session
fn close_session(state: &mut State, session_id: SessionId) -> Vec<u8> {
    let response = state
        .get_session(session_id)
        .encrypt_response(CloseSessionResponse {}.serialize());

    state.close_session(session_id);
    response.into()
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
        ResponseMessage::error(&format!("no such object ID: {:?}", command.object_id))
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
            Algorithm::AES128_CCM_WRAP,
            Algorithm::AES192_CCM_WRAP,
            Algorithm::AES256_CCM_WRAP,
            Algorithm::EC_BP256,
            Algorithm::EC_BP384,
            Algorithm::EC_BP512,
            Algorithm::EC_ECDH,
            Algorithm::EC_ECDSA_SHA1,
            Algorithm::EC_ECDSA_SHA256,
            Algorithm::EC_ECDSA_SHA384,
            Algorithm::EC_ECDSA_SHA512,
            Algorithm::EC_ED25519,
            Algorithm::EC_K256,
            Algorithm::EC_P224,
            Algorithm::EC_P256,
            Algorithm::EC_P384,
            Algorithm::EC_P521,
            Algorithm::HMAC_SHA1,
            Algorithm::HMAC_SHA256,
            Algorithm::HMAC_SHA384,
            Algorithm::HMAC_SHA512,
            Algorithm::MGF1_SHA1,
            Algorithm::MGF1_SHA256,
            Algorithm::MGF1_SHA384,
            Algorithm::MGF1_SHA512,
            Algorithm::OPAQUE_DATA,
            Algorithm::OPAQUE_X509_CERT,
            Algorithm::RSA2048,
            Algorithm::RSA3072,
            Algorithm::RSA4096,
            Algorithm::RSA_OAEP_SHA1,
            Algorithm::RSA_OAEP_SHA256,
            Algorithm::RSA_OAEP_SHA384,
            Algorithm::RSA_OAEP_SHA512,
            Algorithm::RSA_PKCS1_SHA1,
            Algorithm::RSA_PKCS1_SHA256,
            Algorithm::RSA_PKCS1_SHA384,
            Algorithm::RSA_PKCS1_SHA512,
            Algorithm::RSA_PSS_SHA1,
            Algorithm::RSA_PSS_SHA256,
            Algorithm::RSA_PSS_SHA384,
            Algorithm::RSA_PSS_SHA512,
            Algorithm::TEMPL_SSH,
            Algorithm::YUBICO_AES_AUTH,
            Algorithm::YUBICO_OTP_AES128,
            Algorithm::YUBICO_OTP_AES192,
            Algorithm::YUBICO_OTP_AES256,
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
        Ok(ciphertext) => ExportWrappedResponse { nonce, ciphertext }.serialize(),
        Err(e) => ResponseMessage::error(&format!("error wrapping object: {}", e)),
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
    GetLogsResponse {
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
        ResponseMessage::error(&format!("no such object ID: {:?}", command.0.object_id))
    }
}

/// Get an opaque object (X.509 certificate or other data) stored in the HSM
fn get_opaque(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: GetOpaqueCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::GetOpaqueObject: {:?}", e));

    if let Some(obj) = state.objects.get(command.object_id, ObjectType::Opaque) {
        GetOpaqueResponse(obj.payload.as_ref().into()).serialize()
    } else {
        ResponseMessage::error(&format!(
            "no such opaque object ID: {:?}",
            command.object_id
        ))
    }
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
            algorithm: AsymmetricAlgorithm::from_algorithm(obj.algorithm()).unwrap(),
            bytes: obj.payload.public_key_bytes().unwrap(),
        }.serialize()
    } else {
        ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id))
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

    match state.objects.unwrap(wrap_key_id, &nonce, &ciphertext) {
        Ok(obj) => ImportWrappedResponse {
            object_type: obj.object_type,
            object_id: obj.object_id,
        }.serialize(),
        Err(e) => ResponseMessage::error(&format!("error unwrapping object: {}", e)),
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
            id: object.object_info.object_id,
            object_type: object.object_info.object_type,
            sequence: object.object_info.sequence,
        })
        .collect();

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

/// Sign a message using the ECDSA signature algorithm
fn sign_data_ecdsa(state: &State, cmd_data: &[u8]) -> ResponseMessage {
    let command: SignDataECDSACommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing CommandType::SignDataEdDSA: {:?}", e));

    if let Some(obj) = state.objects.get(command.key_id, ObjectType::AsymmetricKey) {
        if let Payload::ECDSAKeyPair(ref key) = obj.payload {
            ECDSASignature(key.sign(command.digest).as_ref().into()).serialize()
        } else {
            ResponseMessage::error(&format!("not an ECDSA key: {:?}", obj.algorithm()))
        }
    } else {
        ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id))
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
            ResponseMessage::error(&format!("not an Ed25519 key: {:?}", obj.algorithm()))
        }
    } else {
        ResponseMessage::error(&format!("no such object ID: {:?}", command.key_id))
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
