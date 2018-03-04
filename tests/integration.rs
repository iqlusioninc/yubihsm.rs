extern crate yubihsm_client;

#[cfg(feature = "mockhsm")]
use std::thread;

use yubihsm_client::{Algorithm, Capabilities, Connector, Domains, ObjectId, ObjectOrigin,
                     ObjectType, Session};
#[cfg(feature = "mockhsm")]
use yubihsm_client::mockhsm::MockHSM;

/// Test against the real yubihsm-connector
#[cfg(not(feature = "mockhsm"))]
const YUBIHSM_ADDR: &str = "127.0.0.1:12345";

// TODO: pick an open port automatically
#[cfg(feature = "mockhsm")]
const MOCKHSM_ADDR: &str = "127.0.0.1:54321";

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Key ID to use for testing keygen/signing
const TEST_KEY_ID: ObjectId = 100;

/// Number of HTTP requests issued by the test suite
///
/// NOTE: This will need to be increased whenever adding additional tests
/// to the suite.
#[cfg(feature = "mockhsm")]
const NUM_HTTP_REQUESTS: usize = 10;

#[cfg(not(feature = "mockhsm"))]
#[test]
fn yubihsm_integration_test() {
    let conn = Connector::open(&format!("http://{}", YUBIHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to yubihsm-connector: {:?}", err));

    let mut session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    // Ignore errors since the object may not exist yet
    let _ = session.delete_object(TEST_KEY_ID, ObjectType::Asymmetric);

    integration_tests(&mut session);
}

#[cfg(feature = "mockhsm")]
fn start_mockhsm() -> thread::JoinHandle<()> {
    thread::spawn(move || MockHSM::new(MOCKHSM_ADDR).unwrap().run(NUM_HTTP_REQUESTS))
}

#[cfg(feature = "mockhsm")]
#[test]
fn mockhsm_integration_test() {
    let mockhsm_thread = start_mockhsm();

    let conn = Connector::open(&format!("http://{}", MOCKHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to mockhsm: {:?}", err));

    let mut session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    integration_tests(&mut session);
    mockhsm_thread.join().unwrap();
}

// Tests to be performed as part of our integration testing process
fn integration_tests(session: &mut Session) {
    // NOTE: if you are adding a new test, you may need to bump NUM_HTTP_TESTS
    // as described at the top of this file
    echo_test(session);
    generate_asymmetric_key_test(session);
    list_objects_test(session);
    delete_object_test(session);
}

// Send a simple echo request
fn echo_test(session: &mut Session) {
    let message = b"Hello, world!";
    let response = session
        .echo(message.as_ref())
        .unwrap_or_else(|err| panic!("error sending echo: {:?}", err));

    assert_eq!(&message[..], &response.message[..]);
}

// Generate an Ed25519 key
fn generate_asymmetric_key_test(session: &mut Session) {
    // Ensure the object does not already exist
    assert!(
        session
            .get_object_info(TEST_KEY_ID, ObjectType::Asymmetric)
            .is_err()
    );

    let label = "yubihsm-client.rs test key";
    let domains = Domains::DOMAIN_1;
    let capabilities = Capabilities::ASYMMETRIC_SIGN_EDDSA;
    let algorithm = Algorithm::EC_ED25519;

    let response = session
        .generate_asymmetric_key(TEST_KEY_ID, label.into(), domains, capabilities, algorithm)
        .unwrap_or_else(|err| panic!("error generating asymmetric key: {:?}", err));

    assert_eq!(response.key_id, TEST_KEY_ID);
    let object_info = session
        .get_object_info(TEST_KEY_ID, ObjectType::Asymmetric)
        .unwrap_or_else(|err| panic!("error getting object info: {:?}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.id, TEST_KEY_ID);
    assert_eq!(object_info.domains, domains);
    assert_eq!(object_info.object_type, ObjectType::Asymmetric);
    assert_eq!(object_info.algorithm, algorithm);
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), label);
}

// List the objects in the YubiHSM2
fn list_objects_test(session: &mut Session) {
    let response = session
        .list_objects()
        .unwrap_or_else(|err| panic!("error listing objects: {:?}", err));

    // Check type of the Ed25519 we created in generate_asymmetric_key_test()
    let object = response.objects.iter().find(|i| i.id == 100).unwrap();
    assert_eq!(object.object_type, ObjectType::Asymmetric)
}

// Delete an object in the YubiHSM2
fn delete_object_test(session: &mut Session) {
    // The first request to delete should succeed because the object exists
    assert!(
        session
            .delete_object(TEST_KEY_ID, ObjectType::Asymmetric)
            .is_ok()
    );

    // The second request to delete should fail because it's already deleted
    assert!(
        session
            .delete_object(TEST_KEY_ID, ObjectType::Asymmetric)
            .is_err()
    );
}
