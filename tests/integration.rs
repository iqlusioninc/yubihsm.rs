/// Integration tests (using live YubiHSM2 or MockHSM)

#[cfg(not(feature = "mockhsm"))]
#[macro_use]
extern crate lazy_static;
extern crate sha2;
extern crate yubihsm;
use yubihsm::{Algorithm, Capability, Domain, ObjectId, ObjectOrigin, ObjectType, Session};

#[cfg(not(feature = "mockhsm"))]
use yubihsm::HttpConnector;

#[cfg(feature = "mockhsm")]
use yubihsm::mockhsm::MockHSM;

#[cfg(feature = "ring")]
extern crate ring;
#[cfg(feature = "ring")]
extern crate untrusted;

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Key ID to use for testing keygen/signing
const TEST_KEY_ID: ObjectId = 100;

/// Label to use for the test key
const TEST_KEY_LABEL: &str = "yubihsm.rs test key";

/// Domain to use for all tests
const TEST_DOMAINS: Domain = Domain::DOM1;

/// Message to sign when performing tests
const TEST_MESSAGE: &[u8] =
    b"The Edwards-curve Digital Signature Algorithm (EdDSA) is a variant of \
      Schnorr's signature system with (possibly twisted) Edwards curves.";

#[cfg(not(feature = "mockhsm"))]
type TestSession = Session<HttpConnector>;

#[cfg(feature = "mockhsm")]
type TestSession = Session<MockHSM>;

#[cfg(not(feature = "mockhsm"))]
lazy_static! {
    static ref SESSION: ::std::sync::Mutex<TestSession> = {
        let session = Session::create_from_password(
            Default::default(),
            DEFAULT_AUTH_KEY_ID,
            DEFAULT_PASSWORD,
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
        MockHSM::create_session(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
            .unwrap_or_else(|err| panic!("error creating MockHSM session: {}", err))
    };
}

/// Create a public key for use in a test
fn create_asymmetric_key(
    session: &mut TestSession,
    algorithm: Algorithm,
    capabilities: Capability,
) {
    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    // Ignore errors since the object may not exist yet
    let _ = yubihsm::delete_object(session, TEST_KEY_ID, ObjectType::Asymmetric);

    // Ensure the object does not already exist
    assert!(yubihsm::get_object_info(session, TEST_KEY_ID, ObjectType::Asymmetric).is_err());

    let response = yubihsm::generate_asymmetric_key(
        session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
    ).unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    assert_eq!(response.key_id, TEST_KEY_ID);
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

    create_asymmetric_key(
        &mut session,
        Algorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    // The first request to delete should succeed because the object exists
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::Asymmetric).is_ok());

    // The second request to delete should fail because it's already deleted
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::Asymmetric).is_err());
}

/// Send a simple echo request
#[test]
fn echo_test() {
    let mut session = create_session!();

    let echo_response = yubihsm::echo(&mut session, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(TEST_MESSAGE, echo_response.as_ref());
}

/// Generate an Ed25519 key
#[test]
fn generate_asymmetric_key_test() {
    let mut session = create_session!();
    let algorithm = Algorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    create_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::Asymmetric)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::Asymmetric);
    assert_eq!(object_info.algorithm, algorithm);
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Get device information
#[test]
fn get_device_info_test() {
    let mut session = create_session!();

    let device_info = yubihsm::get_device_info(&mut session)
        .unwrap_or_else(|err| panic!("error getting device info: {}", err));

    assert_eq!(device_info.major_version, 2);
    assert_eq!(device_info.minor_version, 0);
    assert_eq!(device_info.build_version, 0);
}

/// Get audit log
#[test]
fn get_logs_test() {
    let mut session = create_session!();

    let response =
        yubihsm::get_logs(&mut session).unwrap_or_else(|err| panic!("error getting logs: {}", err));

    assert_eq!(response.num_entries as usize, response.entries.len());
}

/// List the objects in the YubiHSM2
#[test]
fn list_objects_test() {
    let mut session = create_session!();

    create_asymmetric_key(
        &mut session,
        Algorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let objects = yubihsm::list_objects(&mut session)
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Check type of the Ed25519 we created in generate_asymmetric_key_test()
    let object = objects.iter().find(|i| i.id == TEST_KEY_ID).unwrap();

    assert_eq!(object.object_type, ObjectType::Asymmetric)
}

/// Test ECDSA signatures (using NIST P-256)
// TODO: figure out a way to integration test this with *ring*
#[cfg(feature = "ring")]
#[test]
fn sign_ecdsa_test() {
    let mut session = create_session!();

    create_asymmetric_key(
        &mut session,
        Algorithm::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, Algorithm::EC_P256);
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

/// Test Ed25519 signatures
#[cfg(feature = "ring")]
#[test]
fn sign_ed25519_test() {
    let mut session = create_session!();

    create_asymmetric_key(
        &mut session,
        Algorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, Algorithm::EC_ED25519);

    let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(pubkey_response.bytes.as_ref()),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}
