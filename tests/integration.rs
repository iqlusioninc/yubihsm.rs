extern crate yubihsm;

use yubihsm::{
    Algorithm, Capabilities, Connector, Domains, ObjectId, ObjectOrigin, ObjectType, Session,
};

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

/// Domain to use for all tests
const TEST_DOMAINS: Domains = Domains::DOMAIN_1;

/// Message to sign when performing tests
const TEST_MESSAGE: &[u8] = b"The Edwards-curve Digital Signature Algorithm (EdDSA) is a \
        variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

/// Perform a live integration test against yubihsm-connector and a real `YubiHSM2`
#[cfg(not(feature = "mockhsm"))]
#[test]
fn yubihsm_integration_test() {
    let mut session: Session = Session::create_from_password(
        Default::default(),
        DEFAULT_AUTH_KEY_ID,
        DEFAULT_PASSWORD,
        true,
    ).unwrap_or_else(|err| panic!("error creating session: {}", err));

    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    // Ignore errors since the object may not exist yet
    let _ = session.delete_object(TEST_KEY_ID, ObjectType::Asymmetric);

    // Blink the YubiHSM2 for 2 seconds to identify it
    session.blink(2).unwrap();

    integration_tests(&mut session);
}

#[cfg(feature = "mockhsm")]
#[test]
fn mockhsm_integration_test() {
    let mut session = MockHSM::create_session(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating MockHSM session: {}", err));

    integration_tests(&mut session);
}

// Tests to be performed as part of our integration testing process
fn integration_tests<C: Connector>(session: &mut Session<C>) {
    // NOTE: if you are adding a new test, you may need to bump NUM_HTTP_TESTS
    // as described at the top of this file
    echo_test(session);
    generate_asymmetric_key_test(session);
    #[cfg(feature = "ring")]
    sign_ed25519_test(session);
    list_objects_test(session);
    delete_object_test(session);
}

// Send a simple echo request
fn echo_test<C: Connector>(session: &mut Session<C>) {
    let message = b"Hello, world!";
    let response = session
        .echo(message.as_ref())
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(&message[..], &response.message[..]);
}

// Generate an Ed25519 key
fn generate_asymmetric_key_test<C: Connector>(session: &mut Session<C>) {
    // Ensure the object does not already exist
    assert!(
        session
            .get_object_info(TEST_KEY_ID, ObjectType::Asymmetric)
            .is_err()
    );

    let label = "yubihsm.rs test key";
    let capabilities = Capabilities::ASYMMETRIC_SIGN_EDDSA;
    let algorithm = Algorithm::EC_ED25519;

    let response = session
        .generate_asymmetric_key(
            TEST_KEY_ID,
            label.into(),
            TEST_DOMAINS,
            capabilities,
            algorithm,
        )
        .unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    assert_eq!(response.key_id, TEST_KEY_ID);
    let object_info = session
        .get_object_info(TEST_KEY_ID, ObjectType::Asymmetric)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::Asymmetric);
    assert_eq!(object_info.algorithm, algorithm);
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), label);
}

// Compute a signature using the Ed25519 key generated in the last test
#[cfg(feature = "ring")]
fn sign_ed25519_test<C: Connector>(session: &mut Session<C>) {
    let pubkey_response = session
        .get_pubkey(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, Algorithm::EC_ED25519);

    let signature_response = session
        .sign_data_eddsa(TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(&pubkey_response.data),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(&signature_response.signature),
    ).unwrap();
}

// List the objects in the YubiHSM2
fn list_objects_test<C: Connector>(session: &mut Session<C>) {
    let response = session
        .list_objects()
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Check type of the Ed25519 we created in generate_asymmetric_key_test()
    let object = response.objects.iter().find(|i| i.id == 100).unwrap();
    assert_eq!(object.object_type, ObjectType::Asymmetric)
}

// Delete an object in the YubiHSM2
fn delete_object_test<C: Connector>(session: &mut Session<C>) {
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
