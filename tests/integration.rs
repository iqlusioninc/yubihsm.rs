/// Integration tests (using live YubiHSM2 or MockHSM)

#[cfg(not(feature = "mockhsm"))]
#[macro_use]
extern crate lazy_static;
extern crate sha2;
extern crate yubihsm;
use yubihsm::{
    AsymmetricAlgorithm, AuthAlgorithm, AuthKey, Capability, Domain, HMACAlgorithm, ObjectId,
    ObjectOrigin, ObjectType, OpaqueAlgorithm, Session, WrapAlgorithm, AUTH_KEY_DEFAULT_ID,
};

#[cfg(not(feature = "mockhsm"))]
use yubihsm::{HttpConnector, AUTH_KEY_DEFAULT_PASSWORD};

#[cfg(feature = "mockhsm")]
use yubihsm::mockhsm::{MockConnector, MockHSM};

#[cfg(feature = "ring")]
extern crate ring;
#[cfg(feature = "ring")]
extern crate untrusted;

/// Cryptographic test vectors taken from standards documents
mod test_vectors;
use test_vectors::*;

/// Key ID to use for testing keygen/signing
const TEST_KEY_ID: ObjectId = 100;

/// Key ID to use as a keywrapping subject
const TEST_EXPORTED_KEY_ID: ObjectId = 101;

/// Label to use for the test key
const TEST_KEY_LABEL: &str = "yubihsm.rs test key";

/// Label to use for the exported test
const TEST_EXPORTED_KEY_LABEL: &str = "yubihsm.rs exported test key";

/// Domain to use for all tests
const TEST_DOMAINS: Domain = Domain::DOM1;

/// Message to sign when performing tests
const TEST_MESSAGE: &[u8] = b"The YubiHSM2 is a simple, affordable, and secure HSM solution";

/// Size of a NIST P-256 public key
pub const EC_P256_PUBLIC_KEY_SIZE: usize = 64;

#[cfg(not(feature = "mockhsm"))]
type TestSession = Session<HttpConnector>;

#[cfg(feature = "mockhsm")]
type TestSession = Session<MockConnector>;

#[cfg(not(feature = "mockhsm"))]
lazy_static! {
    static ref SESSION: ::std::sync::Mutex<TestSession> = {
        let session = Session::create_from_password(
            Default::default(),
            AUTH_KEY_DEFAULT_ID,
            AUTH_KEY_DEFAULT_PASSWORD,
            true,
        ).unwrap_or_else(|err| panic!("error creating session: {}", err));

        ::std::sync::Mutex::new(session)
    };
}

/// Perform a live integration test against yubihsm-connector and a real `YubiHSM2`
#[cfg(not(feature = "mockhsm"))]
macro_rules! create_session {
    () => {
        SESSION.lock().unwrap()
    };
}

/// Perform an integration test against the MockHSM (useful for CI)
#[cfg(feature = "mockhsm")]
macro_rules! create_session {
    () => {
        MockHSM::new()
            .create_session(AUTH_KEY_DEFAULT_ID, AuthKey::default())
            .unwrap_or_else(|err| panic!("error creating MockHSM session: {}", err))
    };
}

/// Delete the key in the test key slot (if it exists, otherwise do nothing)
fn clear_test_key_slot(session: &mut TestSession, object_type: ObjectType) {
    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    // Ignore errors since the object may not exist yet
    let _ = yubihsm::delete_object(session, TEST_KEY_ID, object_type);

    // Ensure the object does not already exist
    assert!(yubihsm::get_object_info(session, TEST_KEY_ID, object_type).is_err());
}

/// Create a public key for use in a test
fn generate_asymmetric_key(
    session: &mut TestSession,
    algorithm: AsymmetricAlgorithm,
    capabilities: Capability,
) {
    clear_test_key_slot(session, ObjectType::AsymmetricKey);

    let key_id = yubihsm::generate_asymmetric_key(
        session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
    ).unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);
}

/// Put an asymmetric private key into the HSM
fn put_asymmetric_key<T: Into<Vec<u8>>>(
    session: &mut TestSession,
    algorithm: AsymmetricAlgorithm,
    capabilities: Capability,
    data: T,
) {
    clear_test_key_slot(session, ObjectType::AsymmetricKey);

    let key_id = yubihsm::put_asymmetric_key(
        session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
        data,
    ).unwrap_or_else(|err| panic!("error putting asymmetric key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);
}

/// Generate an attestation about a key in the HSM
#[cfg(not(feature = "mockhsm"))]
#[test]
fn attest_asymmetric_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let certificate = yubihsm::attest_asymmetric(&mut session, TEST_KEY_ID, None)
        .unwrap_or_else(|err| panic!("error getting attestation certificate: {}", err));

    // TODO: more tests, e.g. test that the certificate validates
    assert!(certificate.len() > EC_P256_PUBLIC_KEY_SIZE);
}

/// Blink the LED on the YubiHSM for 2 seconds
#[test]
fn blink_test() {
    let mut session = create_session!();
    yubihsm::blink(&mut session, 2).unwrap();
}

/// Delete an object in the YubiHSM2
#[test]
fn delete_object_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    // The first request to delete should succeed because the object exists
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey).is_ok());

    // The second request to delete should fail because it's already deleted
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey).is_err());
}

/// Get device information
#[test]
fn device_info_test() {
    let mut session = create_session!();

    let device_info = yubihsm::device_info(&mut session)
        .unwrap_or_else(|err| panic!("error getting device info: {}", err));

    assert_eq!(device_info.major_version, 2);
    assert_eq!(device_info.minor_version, 0);
    assert_eq!(device_info.build_version, 0);
}

/// Send a simple echo request
#[test]
fn echo_test() {
    let mut session = create_session!();

    let echo_response = yubihsm::echo(&mut session, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(TEST_MESSAGE, echo_response.as_slice());
}

/// Generate an Ed25519 key
#[test]
fn generate_ed25519_key_test() {
    let mut session = create_session!();

    let algorithm = AsymmetricAlgorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    generate_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info =
        yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Generate an Ed25519 key
#[test]
fn generate_hmac_key_test() {
    let mut session = create_session!();

    let algorithm = HMACAlgorithm::HMAC_SHA256;
    let capabilities = Capability::HMAC_DATA | Capability::HMAC_VERIFY;

    clear_test_key_slot(&mut session, ObjectType::HMACKey);

    let key_id = yubihsm::generate_hmac_key(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
    ).unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::HMACKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::HMACKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Generate a NIST P-256 key
#[test]
fn generate_secp256r1_key_test() {
    let mut session = create_session!();
    let algorithm = AsymmetricAlgorithm::EC_P256;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    generate_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info =
        yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Generate an AES-CCM key wrapping key
#[test]
fn generate_wrap_key_test() {
    let mut session = create_session!();

    let algorithm = WrapAlgorithm::AES256_CCM_WRAP;
    let capabilities = Capability::EXPORT_WRAPPED
        | Capability::IMPORT_WRAPPED
        | Capability::UNWRAP_DATA
        | Capability::WRAP_DATA;
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&mut session, ObjectType::WrapKey);

    let key_id = yubihsm::generate_wrap_key(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        delegated_capabilities,
        algorithm,
    ).unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::WrapKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::WrapKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Get audit log
#[test]
fn get_logs_test() {
    let mut session = create_session!();

    // TODO: test audit logging functionality
    yubihsm::get_logs(&mut session).unwrap_or_else(|err| panic!("error getting logs: {}", err));
}

/// Get random bytes
#[test]
fn get_pseudo_random() {
    let mut session = create_session!();

    let bytes = yubihsm::commands::get_pseudo_random::get_pseudo_random(&mut session, 32)
        .unwrap_or_else(|err| panic!("error getting random data: {}", err));

    assert_eq!(32, bytes.len());
}

/// Test HMAC against RFC 4231 test vectors
#[test]
fn hmac_test_vectors() {
    let mut session = create_session!();
    let algorithm = HMACAlgorithm::HMAC_SHA256;
    let capabilities = Capability::HMAC_DATA | Capability::HMAC_VERIFY;

    for vector in HMAC_SHA256_TEST_VECTORS {
        clear_test_key_slot(&mut session, ObjectType::HMACKey);

        let key_id = yubihsm::put_hmac_key(
            &mut session,
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            algorithm,
            vector.key,
        ).unwrap_or_else(|err| panic!("error putting HMAC key: {}", err));

        assert_eq!(key_id, TEST_KEY_ID);

        let tag = yubihsm::hmac(&mut session, TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error computing HMAC of data: {}", err));

        assert_eq!(tag.as_ref(), vector.tag);

        assert!(yubihsm::verify_hmac(&mut session, TEST_KEY_ID, vector.msg, vector.tag).is_ok());

        let mut bad_tag = Vec::from(vector.tag);
        bad_tag[0] ^= 1;

        assert!(yubihsm::verify_hmac(&mut session, TEST_KEY_ID, vector.msg, bad_tag).is_err());
    }
}

/// List the objects in the YubiHSM2
#[test]
fn list_objects_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let objects = yubihsm::list_objects(&mut session)
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Look for the asymmetric key we just generated
    assert!(
        objects
            .iter()
            .find(|i| i.object_id == TEST_KEY_ID && i.object_type == ObjectType::AsymmetricKey)
            .is_some()
    );
}

/// Put an opaquae object and read it back
#[test]
fn opaque_object_test() {
    let mut session = create_session!();

    clear_test_key_slot(&mut session, ObjectType::Opaque);

    let object_id = yubihsm::put_opaque(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        Capability::default(),
        OpaqueAlgorithm::OPAQUE_DATA,
        TEST_MESSAGE,
    ).unwrap_or_else(|err| panic!("error putting opaque object: {}", err));

    assert_eq!(object_id, TEST_KEY_ID);

    let opaque_data = yubihsm::get_opaque(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting opaque object: {}", err));

    assert_eq!(opaque_data, TEST_MESSAGE);
}

/// Put an Ed25519 key
#[test]
fn put_asymmetric_key_test() {
    let mut session = create_session!();
    let algorithm = AsymmetricAlgorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;
    let example_private_key = ED25519_TEST_VECTORS[0].sk;

    put_asymmetric_key(&mut session, algorithm, capabilities, example_private_key);

    let object_info =
        yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Put a new authentication key into the `YubiHSM`
#[test]
fn put_auth_key() {
    let mut session = create_session!();
    let algorithm = AuthAlgorithm::YUBICO_AES_AUTH;
    let capabilities = Capability::all();
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&mut session, ObjectType::AuthKey);

    let new_auth_key = AuthKey::derive_from_password(TEST_MESSAGE);

    let key_id = yubihsm::put_auth_key(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        delegated_capabilities,
        algorithm,
        new_auth_key,
    ).unwrap_or_else(|err| panic!("error putting auth key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AuthKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AuthKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Reset the YubiHSM2 to a factory default state
#[cfg(feature = "mockhsm")]
#[test]
fn reset_test() {
    let session = create_session!();
    yubihsm::reset(session).unwrap();
}

/// Test ECDSA signatures (using NIST P-256)
#[cfg(feature = "ring")]
#[test]
fn sign_ecdsa_secp256r1_with_generated_key_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, AsymmetricAlgorithm::EC_P256);
    assert_eq!(pubkey_response.bytes.len(), 64);

    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04; // DER OCTET STRING tag
    pubkey[1..].copy_from_slice(pubkey_response.bytes.as_slice());

    let signature = yubihsm::sign_ecdsa_sha2(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing ECDSA signature: {}", err));

    ring::signature::verify(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        untrusted::Input::from(&pubkey),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}

/// Test Ed25519 against RFC 8032 test vectors
#[test]
fn sign_ed25519_test_vectors() {
    let mut session = create_session!();

    for vector in ED25519_TEST_VECTORS {
        put_asymmetric_key(
            &mut session,
            AsymmetricAlgorithm::EC_ED25519,
            Capability::ASYMMETRIC_SIGN_EDDSA,
            vector.sk,
        );

        let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {}", err));

        assert_eq!(pubkey_response.algorithm, AsymmetricAlgorithm::EC_ED25519);
        assert_eq!(pubkey_response.bytes, vector.pk);

        let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

        assert_eq!(signature.as_ref(), vector.sig);
    }
}

/// Test Ed25519 signing using a randomly generated HSM key
#[cfg(feature = "ring")]
#[test]
fn sign_ed25519_with_generated_key_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let pubkey = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey.algorithm, AsymmetricAlgorithm::EC_ED25519);

    let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(pubkey.bytes.as_ref()),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}

/// Get stats about currently free storage
#[test]
fn storage_status_test() {
    let mut session = create_session!();

    let response = yubihsm::storage_status(&mut session)
        .unwrap_or_else(|err| panic!("error getting storage status: {}", err));

    // TODO: these will probably have to change if Yubico releases new models
    assert_eq!(response.total_records, 256);
    assert_eq!(response.total_pages, 1024);
    assert_eq!(response.page_size, 126);
}

/// Test wrap key workflow using randomly generated keys
// TODO: test against RFC 3610 vectors
#[test]
fn wrap_key_test() {
    let mut session = create_session!();
    let algorithm = WrapAlgorithm::AES128_CCM_WRAP;
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&mut session, ObjectType::WrapKey);

    let key_id = yubihsm::put_wrap_key(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        delegated_capabilities,
        algorithm,
        AESCCM_TEST_VECTORS[0].key,
    ).unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    // Create a key to export
    let exported_key_type = ObjectType::AsymmetricKey;
    let exported_key_capabilities =
        Capability::ASYMMETRIC_SIGN_EDDSA | Capability::EXPORT_UNDER_WRAP;
    let exported_key_algorithm = AsymmetricAlgorithm::EC_ED25519;

    let _ = yubihsm::delete_object(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type);
    yubihsm::generate_asymmetric_key(
        &mut session,
        TEST_EXPORTED_KEY_ID,
        TEST_EXPORTED_KEY_LABEL.into(),
        TEST_DOMAINS,
        exported_key_capabilities,
        exported_key_algorithm,
    ).unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    let wrap_data = yubihsm::export_wrapped(
        &mut session,
        TEST_KEY_ID,
        exported_key_type,
        TEST_EXPORTED_KEY_ID,
    ).unwrap_or_else(|err| panic!("error exporting key: {}", err));

    // Delete the object from the HSM prior to re-importing it
    assert!(yubihsm::delete_object(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type).is_ok());

    // Re-import the wrapped key back into the HSM
    let import_response = yubihsm::import_wrapped(&mut session, TEST_KEY_ID, wrap_data)
        .unwrap_or_else(|err| panic!("error importing key: {}", err));

    assert_eq!(import_response.object_type, exported_key_type);
    assert_eq!(import_response.object_id, TEST_EXPORTED_KEY_ID);

    let imported_key_info =
        yubihsm::get_object_info(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(imported_key_info.capabilities, exported_key_capabilities);
    assert_eq!(imported_key_info.object_id, TEST_EXPORTED_KEY_ID);
    assert_eq!(imported_key_info.domains, TEST_DOMAINS);
    assert_eq!(imported_key_info.object_type, exported_key_type);
    assert_eq!(imported_key_info.algorithm, exported_key_algorithm.into());
    assert_eq!(imported_key_info.origin, ObjectOrigin::WrappedGenerated);
    assert_eq!(
        &imported_key_info.label.to_string().unwrap(),
        TEST_EXPORTED_KEY_LABEL
    );
}
