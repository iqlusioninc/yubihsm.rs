//! Commands supported by the `MockHsm`

use super::{object::Payload, state::State, MOCK_SERIAL_NUMBER};
use crate::{
    algorithm::*,
    asymmetric::{self, commands::*, PublicKey},
    audit::{commands::*, AuditCommand, AuditOption, AuditTag},
    authentication::{self, commands::*},
    command::{Code, Message},
    connector,
    device::{self, commands::*, SerialNumber, StorageInfo},
    ecdh,
    ecdsa::{self, commands::*},
    ed25519::commands::*,
    hmac::{self, commands::*},
    object::{self, commands::*},
    opaque::{self, commands::*},
    otp,
    response::{self, Response},
    rsa::{
        self, mgf,
        oaep::{commands::*, DecryptedData},
        pkcs1::commands::*,
        pss::commands::*,
    },
    serialization::deserialize,
    session::{self, commands::*},
    template,
    wrap::{self, commands::*},
    Capability,
};
use ::ecdsa::{
    elliptic_curve::{bigint::U256, generic_array::GenericArray, ops::Reduce, Field},
    hazmat::SignPrimitive,
};
use ::hmac::{Hmac, Mac};
use ::rsa::{oaep::Oaep, pkcs1v15, pss, traits::PaddingScheme, RsaPrivateKey};
use digest::{
    const_oid::AssociatedOid, crypto_common::OutputSizeUser, typenum::Unsigned, Digest,
    FixedOutput, FixedOutputReset, Output, Reset,
};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use signature::{
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
    Signer,
};
use std::{io::Cursor, str::FromStr};
use subtle::ConstantTimeEq;

/// Create a new HSM session
pub(crate) fn create_session(
    state: &mut State,
    cmd_message: &Message,
) -> Result<Vec<u8>, connector::Error> {
    let cmd: CreateSessionCommand = deserialize(cmd_message.data.as_ref())
        .unwrap_or_else(|e| panic!("error parsing CreateSession command data: {e:?}"));

    let session = state.create_session(cmd.authentication_key_id, cmd.host_challenge);

    let mut response = CreateSessionResponse {
        card_challenge: *session.card_challenge(),
        card_cryptogram: session.card_cryptogram(),
    }
    .serialize();

    response.session_id = Some(session.id);
    Ok(response.into())
}

/// Authenticate an HSM session
pub(crate) fn authenticate_session(
    state: &mut State,
    command: &Message,
) -> Result<Vec<u8>, connector::Error> {
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
    encrypted_command: Message,
) -> Result<Vec<u8>, connector::Error> {
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
        Code::BlinkDevice => BlinkDeviceResponse {}.serialize(),
        Code::CloseSession => return close_session(state, session_id),
        Code::DeleteObject => delete_object(state, &command.data),
        Code::DeviceInfo => device_info(),
        Code::Echo => echo(&command.data),
        Code::ExportWrapped => export_wrapped(state, &command.data),
        Code::GenerateAsymmetricKey => gen_asymmetric_key(state, &command.data),
        Code::GenerateHmacKey => gen_hmac_key(state, &command.data),
        Code::GenerateWrapKey => gen_wrap_key(state, &command.data),
        Code::GetLogEntries => get_log_entries(),
        Code::GetObjectInfo => get_object_info(state, &command.data),
        Code::GetOpaqueObject => get_opaque(state, &command.data),
        Code::GetOption => get_option(state, &command.data),
        Code::GetPseudoRandom => get_pseudo_random(state, &command.data),
        Code::GetPublicKey => get_public_key(state, &command.data),
        Code::SignHmac => sign_hmac(state, &command.data),
        Code::ImportWrapped => import_wrapped(state, &command.data),
        Code::ListObjects => list_objects(state, &command.data),
        Code::PutAsymmetricKey => put_asymmetric_key(state, &command.data),
        Code::PutAuthenticationKey => put_authentication_key(state, &command.data),
        Code::PutHmacKey => put_hmac_key(state, &command.data),
        Code::PutOpaqueObject => put_opaque(state, &command.data),
        Code::SetOption => put_option(state, &command.data),
        Code::PutWrapKey => put_wrap_key(state, &command.data),
        Code::ResetDevice => return Ok(reset_device(state, session_id)),
        Code::SetLogIndex => SetLogIndexResponse {}.serialize(),
        Code::SignEcdsa => sign_ecdsa(state, &command.data),
        Code::SignEddsa => sign_eddsa(state, &command.data),
        Code::GetStorageInfo => get_storage_info(),
        Code::VerifyHmac => verify_hmac(state, &command.data),
        Code::SignPss => sign_pss(state, &command.data),
        Code::SignPkcs1 => sign_pkcs1v15(state, &command.data),
        Code::DecryptOaep => decrypt_oaep(state, &command.data),
        unsupported => panic!("unsupported command type: {unsupported:?}"),
    };

    Ok(state
        .get_session(session_id)?
        .encrypt_response(response)
        .into())
}

/// Close an active session
fn close_session(state: &mut State, session_id: session::Id) -> Result<Vec<u8>, connector::Error> {
    let response = state
        .get_session(session_id)?
        .encrypt_response(CloseSessionResponse {}.serialize());

    state.close_session(session_id);
    Ok(response.into())
}

/// Delete an object
fn delete_object(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let command: DeleteObjectCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::DeleteObject: {e:?}"));

    if state
        .objects
        .remove(command.object_id, command.object_type)
        .is_some()
    {
        DeleteObjectResponse {}.serialize()
    } else {
        debug!("no such object ID: {:?}", command.object_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Generate a mock device information report
fn device_info() -> response::Message {
    let info = device::Info {
        major_version: 2,
        minor_version: 0,
        build_version: 0,
        serial_number: SerialNumber::from_str(MOCK_SERIAL_NUMBER).unwrap(),
        log_store_capacity: 62,
        log_store_used: 62,
        algorithms: vec![
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha1)),
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha256)),
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha384)),
            Algorithm::Rsa(rsa::Algorithm::Pkcs1(rsa::pkcs1::Algorithm::Sha512)),
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha1)),
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha256)),
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha384)),
            Algorithm::Rsa(rsa::Algorithm::Pss(rsa::pss::Algorithm::Sha512)),
            Algorithm::Asymmetric(asymmetric::Algorithm::Rsa2048),
            Algorithm::Asymmetric(asymmetric::Algorithm::Rsa3072),
            Algorithm::Asymmetric(asymmetric::Algorithm::Rsa4096),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcP256),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcP384),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcP521),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcK256),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcBp256),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcBp384),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcBp512),
            Algorithm::Hmac(hmac::Algorithm::Sha1),
            Algorithm::Hmac(hmac::Algorithm::Sha256),
            Algorithm::Hmac(hmac::Algorithm::Sha384),
            Algorithm::Hmac(hmac::Algorithm::Sha512),
            Algorithm::Ecdsa(ecdsa::Algorithm::Sha1),
            Algorithm::Ecdh(ecdh::Algorithm::Ecdh),
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha1)),
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha256)),
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha384)),
            Algorithm::Rsa(rsa::Algorithm::Oaep(rsa::oaep::Algorithm::Sha512)),
            Algorithm::Wrap(wrap::Algorithm::Aes128Ccm),
            Algorithm::Opaque(opaque::Algorithm::Data),
            Algorithm::Opaque(opaque::Algorithm::X509Certificate),
            Algorithm::Mgf(mgf::Algorithm::Sha1),
            Algorithm::Mgf(mgf::Algorithm::Sha256),
            Algorithm::Mgf(mgf::Algorithm::Sha384),
            Algorithm::Mgf(mgf::Algorithm::Sha512),
            Algorithm::Template(template::Algorithm::Ssh),
            Algorithm::YubicoOtp(otp::Algorithm::Aes128),
            Algorithm::Authentication(authentication::Algorithm::YubicoAes),
            Algorithm::YubicoOtp(otp::Algorithm::Aes192),
            Algorithm::YubicoOtp(otp::Algorithm::Aes256),
            Algorithm::Wrap(wrap::Algorithm::Aes192Ccm),
            Algorithm::Wrap(wrap::Algorithm::Aes256Ccm),
            Algorithm::Ecdsa(ecdsa::Algorithm::Sha256),
            Algorithm::Ecdsa(ecdsa::Algorithm::Sha384),
            Algorithm::Ecdsa(ecdsa::Algorithm::Sha512),
            Algorithm::Asymmetric(asymmetric::Algorithm::Ed25519),
            Algorithm::Asymmetric(asymmetric::Algorithm::EcP224),
        ],
    };

    DeviceInfoResponse(info).serialize()
}

/// Echo a message back to the host
fn echo(cmd_data: &[u8]) -> response::Message {
    EchoResponse(cmd_data.into()).serialize()
}

/// Export an object from the HSM in encrypted form
fn export_wrapped(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let ExportWrappedCommand {
        wrap_key_id,
        object_type,
        object_id,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::ExportWrapped: {e:?}"));

    let nonce = wrap::Nonce::generate();

    match state
        .objects
        .wrap_obj(wrap_key_id, object_id, object_type, &nonce)
    {
        Ok(ciphertext) => ExportWrappedResponse(wrap::Message { nonce, ciphertext }).serialize(),
        Err(e) => {
            debug!("error wrapping object: {}", e);
            device::ErrorKind::InvalidCommand.into()
        }
    }
}

/// Generate a new random asymmetric key
fn gen_asymmetric_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let GenAsymmetricKeyCommand(command) = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::GenAsymmetricKey: {e:?}"));

    state.objects.generate(
        command.key_id,
        object::Type::AsymmetricKey,
        command.algorithm,
        command.label,
        command.capabilities,
        Capability::default(),
        command.domains,
    );

    GenAsymmetricKeyResponse {
        key_id: command.key_id,
    }
    .serialize()
}

/// Generate a new random HMAC key
fn gen_hmac_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let GenHmacKeyCommand(command) =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::GenHMACKey: {e:?}"));

    state.objects.generate(
        command.key_id,
        object::Type::HmacKey,
        command.algorithm,
        command.label,
        command.capabilities,
        Capability::default(),
        command.domains,
    );

    GenHmacKeyResponse {
        key_id: command.key_id,
    }
    .serialize()
}

/// Generate a new random wrap (i.e. AES-CCM) key
fn gen_wrap_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let GenWrapKeyCommand {
        params,
        delegated_capabilities,
    } = deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::GenWrapKey: {e:?}"));

    state.objects.generate(
        params.key_id,
        object::Type::WrapKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
    );

    GenWrapKeyResponse {
        key_id: params.key_id,
    }
    .serialize()
}

/// Get mock log information
fn get_log_entries() -> response::Message {
    // TODO: mimic the YubiHSM's actual audit log
    LogEntries {
        unlogged_boot_events: 0,
        unlogged_auth_events: 0,
        num_entries: 0,
        entries: vec![],
    }
    .serialize()
}

/// Get detailed info about a specific object
fn get_object_info(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: GetObjectInfoCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::GetObjectInfo: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.0.object_id, command.0.object_type)
    {
        GetObjectInfoResponse(obj.object_info.clone()).serialize()
    } else {
        debug!("no such object ID: {:?}", command.0.object_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Get an opaque object (X.509 certificate or other data) stored in the HSM
fn get_opaque(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: GetOpaqueCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::GetOpaqueObject: {e:?}"));

    if let Some(obj) = state.objects.get(command.object_id, object::Type::Opaque) {
        GetOpaqueResponse(obj.payload.to_bytes()).serialize()
    } else {
        debug!("no such opaque object ID: {:?}", command.object_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Get an auditing option
fn get_option(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: GetOptionCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::GetOpaqueObject: {e:?}"));

    let results = match command.tag {
        AuditTag::Command => state.command_audit_options.serialize(),
        AuditTag::Force => vec![state.force_audit.to_u8()],
        AuditTag::Fips => vec![state.fips.to_u8()],
    };

    GetOptionResponse(results).serialize()
}

/// Get bytes of random data
fn get_pseudo_random(_state: &State, cmd_data: &[u8]) -> response::Message {
    let command: GetPseudoRandomCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::GetPseudoRandom: {e:?}"));

    let mut bytes = vec![0u8; command.bytes as usize];
    OsRng.fill_bytes(&mut bytes);

    GetPseudoRandomResponse { bytes }.serialize()
}

/// Get the public key associated with a key in the HSM
fn get_public_key(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: GetPublicKeyCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::GetPubKey: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        GetPublicKeyResponse(PublicKey {
            algorithm: obj.algorithm().asymmetric().unwrap(),
            bytes: obj.payload.public_key_bytes().unwrap(),
        })
        .serialize()
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Generate a mock storage status report
fn get_storage_info() -> response::Message {
    // TODO: model actual free storage
    let info = StorageInfo {
        total_records: 256,
        free_records: 256,
        total_pages: 1024,
        free_pages: 1024,
        page_size: 126,
    };

    GetStorageInfoResponse(info).serialize()
}

/// Import an object encrypted under a wrap key into the HSM
fn import_wrapped(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let ImportWrappedCommand {
        wrap_key_id,
        nonce,
        ciphertext,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::ImportWrapped: {e:?}"));

    match state.objects.unwrap_obj(wrap_key_id, &nonce, ciphertext) {
        Ok(obj) => ImportWrappedResponse {
            object_type: obj.object_type,
            object_id: obj.object_id,
        }
        .serialize(),
        Err(e) => {
            debug!("error unwrapping object: {}", e);
            device::ErrorKind::InvalidCommand.into()
        }
    }
}

/// List all objects presently accessible to a session
fn list_objects(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: ListObjectsCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::ListObjects: {e:?}"));

    let len = command.0.len() as u64;
    let mut cursor = Cursor::new(command.0);
    let mut filters = vec![];

    while cursor.position() < len {
        filters.push(object::Filter::deserialize(&mut cursor).unwrap());
    }

    let list_entries = state
        .objects
        .iter()
        .filter(|(_, object)| {
            if filters.is_empty() {
                true
            } else {
                filters.iter().all(|filter| match filter {
                    object::Filter::Algorithm(alg) => object.info().algorithm == *alg,
                    object::Filter::Capabilities(caps) => {
                        object.info().capabilities.contains(*caps)
                    }
                    object::Filter::Domains(doms) => object.info().domains.contains(*doms),
                    object::Filter::Label(label) => object.info().label == *label,
                    object::Filter::Id(id) => object.info().object_id == *id,
                    object::Filter::Type(ty) => object.info().object_type == *ty,
                })
            }
        })
        .map(|(_, object)| object::Entry::from(object))
        .collect();

    ListObjectsResponse(list_entries).serialize()
}

/// Put an existing asymmetric key into the HSM
fn put_asymmetric_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let PutAsymmetricKeyCommand { params, data } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::PutAsymmetricKey: {e:?}"));

    state.objects.put(
        params.id,
        object::Type::AsymmetricKey,
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
fn put_authentication_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let PutAuthenticationKeyCommand {
        params,
        delegated_capabilities,
        authentication_key,
    } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::PutAuthenticationKey: {e:?}"));

    state.objects.put(
        params.id,
        object::Type::AuthenticationKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
        &authentication_key.0,
    );

    PutAuthenticationKeyResponse { key_id: params.id }.serialize()
}

/// Put a new HMAC key into the HSM
fn put_hmac_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let PutHmacKeyCommand { params, hmac_key } =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::PutHMACKey: {e:?}"));

    state.objects.put(
        params.id,
        object::Type::HmacKey,
        params.algorithm,
        params.label,
        params.capabilities,
        Capability::default(),
        params.domains,
        &hmac_key,
    );

    PutHmacKeyResponse { key_id: params.id }.serialize()
}

/// Put an opaque object (X.509 cert or other data) into the HSM
fn put_opaque(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let PutOpaqueCommand { params, data } = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::PutOpaqueObject: {e:?}"));

    state.objects.put(
        params.id,
        object::Type::Opaque,
        params.algorithm,
        params.label,
        params.capabilities,
        Capability::default(),
        params.domains,
        &data,
    );

    PutOpaqueResponse {
        object_id: params.id,
    }
    .serialize()
}

/// Change an HSM auditing setting
fn put_option(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let SetOptionCommand { tag, length, value } =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::PutOption: {e:?}"));

    match tag {
        AuditTag::Force => {
            assert_eq!(length, 1);
            state.force_audit = AuditOption::from_u8(value[0]).unwrap()
        }
        AuditTag::Command => {
            assert_eq!(length, 2);
            let audit_cmd: AuditCommand =
                deserialize(&value).unwrap_or_else(|e| panic!("error parsing AuditCommand: {e:?}"));

            state
                .command_audit_options
                .put(audit_cmd.command_type(), audit_cmd.audit_option());
        }
        AuditTag::Fips => {
            assert_eq!(length, 1);
            state.fips = AuditOption::from_u8(value[0]).unwrap()
        }
    }

    PutOptionResponse {}.serialize()
}

/// Put an existing wrap (i.e. AES-CCM) key into the HSM
fn put_wrap_key(state: &mut State, cmd_data: &[u8]) -> response::Message {
    let PutWrapKeyCommand {
        params,
        delegated_capabilities,
        data,
    } = deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::PutWrapKey: {e:?}"));

    state.objects.put(
        params.id,
        object::Type::WrapKey,
        params.algorithm,
        params.label,
        params.capabilities,
        delegated_capabilities,
        params.domains,
        &data,
    );

    PutWrapKeyResponse { key_id: params.id }.serialize()
}

/// Reset the MockHsm back to its default state
fn reset_device(state: &mut State, session_id: session::Id) -> Vec<u8> {
    let response = state
        .get_session(session_id)
        .unwrap()
        .encrypt_response(ResetDeviceResponse(0x01).serialize())
        .into();

    state.reset();
    response
}

/// Sign a message using the ECDSA signature algorithm
fn sign_ecdsa(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: SignEcdsaCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::SignEcdsa: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        match &obj.payload {
            Payload::EcdsaNistP256(secret_key) => {
                let k = p256::Scalar::random(&mut OsRng);
                let z = p256::Scalar::reduce_bytes(GenericArray::from_slice(&command.digest))
                    .to_bytes();
                let signature = secret_key
                    .to_nonzero_scalar()
                    .try_sign_prehashed(k, &z)
                    .expect("ECDSA failure!")
                    .0;

                SignEcdsaResponse(signature.to_der().as_ref().into()).serialize()
            }
            Payload::EcdsaSecp256k1(secret_key) => {
                let k = k256::Scalar::random(&mut OsRng);
                let z = <k256::Scalar as Reduce<U256>>::reduce_bytes(GenericArray::from_slice(
                    &command.digest,
                ))
                .to_bytes();
                let signature = secret_key
                    .to_nonzero_scalar()
                    .try_sign_prehashed(k, &z)
                    .expect("ECDSA failure!")
                    .0;

                SignEcdsaResponse(signature.to_der().as_ref().into()).serialize()
            }
            _ => {
                debug!("not an ECDSA key: {:?}", obj.algorithm());
                device::ErrorKind::InvalidCommand.into()
            }
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Sign a message using the Ed25519 signature algorithm
fn sign_eddsa(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: SignEddsaCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::SignEdDSA: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        if let Payload::Ed25519Key(signing_key) = &obj.payload {
            let signature = signing_key.sign(command.data.as_ref());
            SignEddsaResponse(signature.to_bytes().into()).serialize()
        } else {
            debug!("not an Ed25519 key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Compute the HMAC tag for the given data
fn sign_hmac(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: SignHmacCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::HMACData: {e:?}"));

    if let Some(obj) = state.objects.get(command.key_id, object::Type::HmacKey) {
        if let Payload::HmacKey(alg, ref key) = obj.payload {
            assert_eq!(alg, hmac::Algorithm::Sha256);
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(&command.data);
            let tag = mac.finalize();
            SignHmacResponse(hmac::Tag(tag.into_bytes().as_slice().into())).serialize()
        } else {
            debug!("not an HMAC key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Sign a message using the RSASSA-PSS signature algorithm
fn sign_pss(state: &State, cmd_data: &[u8]) -> response::Message {
    #[inline]
    fn sign_pss_digest<D: Digest + FixedOutputReset>(
        private_key: &RsaPrivateKey,
        msg: &[u8],
    ) -> pss::Signature {
        let signing_key = pss::SigningKey::<D>::new(private_key.clone());
        signing_key
            .sign_prehash_with_rng(&mut OsRng, msg)
            .expect("unable to sign with prehash, wrong payload length?")
    }

    let command: SignPssCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::SignPss: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        if let Payload::RsaKey(private_key) = &obj.payload {
            let signature = match command.mgf1_hash_alg {
                mgf::Algorithm::Sha1 => {
                    sign_pss_digest::<Sha1>(private_key, command.digest.as_ref())
                }
                mgf::Algorithm::Sha256 => {
                    sign_pss_digest::<Sha256>(private_key, command.digest.as_ref())
                }
                mgf::Algorithm::Sha384 => {
                    sign_pss_digest::<Sha384>(private_key, command.digest.as_ref())
                }
                mgf::Algorithm::Sha512 => {
                    sign_pss_digest::<Sha512>(private_key, command.digest.as_ref())
                }
            };

            SignPssResponse((&signature).into()).serialize()
        } else {
            debug!("not an Rsa key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Sign a message using the RSASSA-PKCS1-v1_5 signature algorithm
fn sign_pkcs1v15(state: &State, cmd_data: &[u8]) -> response::Message {
    #[inline]
    fn sign_pkcs1v15_prehash<D: Digest + AssociatedOid>(
        private_key: &RsaPrivateKey,
        prehash: &[u8],
    ) -> pkcs1v15::Signature {
        let signing_key = pkcs1v15::SigningKey::<D>::new(private_key.clone());
        signing_key
            .sign_prehash(prehash)
            .expect("unable to sign with prehash, wrong payload length?")
    }

    let command: SignPkcs1Command =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::SignPss: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        if let Payload::RsaKey(private_key) = &obj.payload {
            let signature = match command.digest.len() {
                len if len == <Sha1 as OutputSizeUser>::OutputSize::USIZE => {
                    sign_pkcs1v15_prehash::<Sha1>(private_key, command.digest.as_ref())
                }
                len if len == <Sha256 as OutputSizeUser>::OutputSize::USIZE => {
                    sign_pkcs1v15_prehash::<Sha256>(private_key, command.digest.as_ref())
                }
                len if len == <Sha384 as OutputSizeUser>::OutputSize::USIZE => {
                    sign_pkcs1v15_prehash::<Sha384>(private_key, command.digest.as_ref())
                }
                len if len == <Sha512 as OutputSizeUser>::OutputSize::USIZE => {
                    sign_pkcs1v15_prehash::<Sha512>(private_key, command.digest.as_ref())
                }
                len => {
                    debug!("invalid digest length: {}", len);
                    return device::ErrorKind::InvalidCommand.into();
                }
            };

            SignPkcs1Response((&signature).into()).serialize()
        } else {
            debug!("not an Rsa key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// Verify the HMAC tag for the given data
fn verify_hmac(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: VerifyHmacCommand =
        deserialize(cmd_data).unwrap_or_else(|e| panic!("error parsing Code::HMACData: {e:?}"));

    if let Some(obj) = state.objects.get(command.key_id, object::Type::HmacKey) {
        if let Payload::HmacKey(alg, ref key) = obj.payload {
            assert_eq!(alg, hmac::Algorithm::Sha256);

            // Because of a quirk of our serde parser everything winds up in the tag field
            let data = command.tag.into_vec();

            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(&data[32..]);
            let tag = mac.finalize().into_bytes();
            let is_ok = tag.as_slice().ct_eq(&data[..32]).unwrap_u8();

            VerifyHmacResponse(is_ok).serialize()
        } else {
            debug!("not an HMAC key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}

/// [`PrecomputedHashDigest`] provides a backend for storing a fixed hash.
///
/// When an OAEP decrypt command is sent by the client, it will carry the hash of the label (and
/// not the label itself).
/// Sadly [`::rsa::oaep::Oaep`] implementation for decrypt does not accept that but expects an object
/// implementing [`Digest`]. If you don't provide a label, it will feed an empty slice to the
/// digest and use its output.
///
/// [`PrecomputedHashDigest`] provides a compatible implementation, but will ignore whatever
/// it's fed, and only reply with the pre-hashed content instead.
///
/// # Panics
///
/// Trying to reset the fixed hash will trigger a panic, and should be treated as a
/// bug.
#[derive(Clone)]
struct PrecomputedHashDigest<D: OutputSizeUser> {
    fixed: GenericArray<u8, D::OutputSize>,
}

impl<D: OutputSizeUser> OutputSizeUser for PrecomputedHashDigest<D> {
    type OutputSize = D::OutputSize;
    fn output_size() -> usize {
        D::output_size()
    }
}

impl<D: OutputSizeUser> FixedOutput for PrecomputedHashDigest<D> {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.clone_from_slice(self.fixed.as_slice())
    }
}

impl<D: OutputSizeUser> digest::Update for PrecomputedHashDigest<D> {
    fn update(&mut self, _data: &[u8]) {}
}

impl<D: OutputSizeUser> Reset for PrecomputedHashDigest<D> {
    fn reset(&mut self) {
        unimplemented!("Tried to update PrecomputedHashDigest, this is unexpected")
    }
}

impl<D: OutputSizeUser> FixedOutputReset for PrecomputedHashDigest<D> {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        out.clone_from_slice(self.fixed.as_slice())
    }
}

fn decrypt_oaep(state: &State, cmd_data: &[u8]) -> response::Message {
    let command: DecryptOaepCommand = deserialize(cmd_data)
        .unwrap_or_else(|e| panic!("error parsing Code::DecryptOaepCommand: {e:?}"));

    if let Some(obj) = state
        .objects
        .get(command.key_id, object::Type::AsymmetricKey)
    {
        if let Payload::RsaKey(private_key) = &obj.payload {
            macro_rules! decrypt_oaep {
                ($hash:ty) => {{
                    let oaep = Oaep {
                        digest: Box::new(PrecomputedHashDigest::<$hash> {
                            fixed: GenericArray::clone_from_slice(command.label_hash.as_slice()),
                        }),
                        mgf_digest: Box::new(<$hash>::new()),
                        label: None,
                    };
                    oaep.decrypt(Some(&mut OsRng), private_key, &command.data)
                }};
            }

            let plaintext = match command.mgf1_hash_alg {
                mgf::Algorithm::Sha1 => {
                    decrypt_oaep!(Sha1)
                }
                mgf::Algorithm::Sha256 => {
                    decrypt_oaep!(Sha256)
                }
                mgf::Algorithm::Sha384 => {
                    decrypt_oaep!(Sha384)
                }
                mgf::Algorithm::Sha512 => {
                    decrypt_oaep!(Sha512)
                }
            };

            let plaintext = if let Ok(plaintext) = plaintext {
                plaintext
            } else {
                debug!("decrypt failed");
                return device::ErrorKind::InvalidData.into();
            };

            DecryptOaepResponse(DecryptedData(plaintext)).serialize()
        } else {
            debug!("not an Rsa key: {:?}", obj.algorithm());
            device::ErrorKind::InvalidCommand.into()
        }
    } else {
        debug!("no such object ID: {:?}", command.key_id);
        device::ErrorKind::ObjectNotFound.into()
    }
}
