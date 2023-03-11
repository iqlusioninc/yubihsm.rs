//! Ed25519 tests

use ed25519_dalek::{Verifier, VerifyingKey};
use yubihsm::{asymmetric::signature::Signer as _, ed25519, Client};

/// Key ID to use for test key
const TEST_SIGNING_KEY_ID: yubihsm::object::Id = 200;

/// Domain IDs for test key
const TEST_SIGNING_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

/// Capability for test key
const TEST_SIGNING_KEY_CAPABILITIES: yubihsm::Capability = yubihsm::Capability::SIGN_EDDSA;

/// Label for test key
const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

/// Example message to sign
const TEST_MESSAGE: &[u8] =
    b"The Edwards-curve Digital Signature yubihsm::asymmetric::Algorithm  (EdDSA) is a \
        variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

/// Create the key on the YubiHSM to use for this test
fn create_yubihsm_key(client: &Client) {
    // Delete the key in TEST_KEY_ID slot it exists
    // Ignore errors since the object may not exist yet
    let _ = client.delete_object(TEST_SIGNING_KEY_ID, yubihsm::object::Type::AsymmetricKey);

    // Create a new key for testing
    client
        .generate_asymmetric_key(
            TEST_SIGNING_KEY_ID,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            TEST_SIGNING_KEY_CAPABILITIES,
            yubihsm::asymmetric::Algorithm::Ed25519,
        )
        .unwrap();
}

#[test]
fn ed25519_sign_test() {
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client);

    let signer = ed25519::Signer::create(client.clone(), TEST_SIGNING_KEY_ID).unwrap();
    let signature = signer.sign(TEST_MESSAGE);

    let verifier = VerifyingKey::from_bytes(signer.public_key().as_bytes()).unwrap();
    assert!(verifier.verify(TEST_MESSAGE, &signature).is_ok());
}
