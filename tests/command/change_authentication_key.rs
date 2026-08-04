use yubihsm::{authentication, object, Capability};

use crate::{TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};

const OLD_PASSWORD: &[u8] = b"original password";
const NEW_PASSWORD: &[u8] = b"replacement password";

/// Provision an authentication key at `TEST_KEY_ID` on a fresh HSM, using the
/// default admin credentials, and return a connector for it.
///
/// Each test gets its own HSM instance: rotating an authentication key
/// invalidates credentials, which would otherwise break the shared test client
/// part-way through the suite.
fn provision() -> yubihsm::Connector {
    let connector = crate::create_hsm_connector();

    let admin = yubihsm::Client::open(connector.clone(), Default::default(), true)
        .unwrap_or_else(|err| panic!("error opening admin session: {err}"));

    admin
        .put_authentication_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            Capability::all(),
            Capability::all(),
            authentication::Algorithm::YubicoAes,
            authentication::Key::derive_from_password(OLD_PASSWORD),
        )
        .unwrap_or_else(|err| panic!("error putting auth key: {err}"));

    connector
}

/// Changing the key that established the current session replaces its key
/// material and preserves all of its metadata.
#[test]
fn change_authentication_key() {
    let connector = provision();
    let algorithm = authentication::Algorithm::YubicoAes;

    let mut client = yubihsm::Client::open(
        connector.clone(),
        yubihsm::Credentials::from_password(TEST_KEY_ID, OLD_PASSWORD),
        true,
    )
    .unwrap_or_else(|err| panic!("error opening session with original key: {err}"));

    let changed_id = client
        .change_authentication_key(
            TEST_KEY_ID,
            algorithm,
            authentication::Key::derive_from_password(NEW_PASSWORD),
        )
        .unwrap_or_else(|err| panic!("error changing auth key: {err}"));

    assert_eq!(changed_id, TEST_KEY_ID);

    // Metadata must survive the rotation.
    let object_info = client
        .get_object_info(TEST_KEY_ID, object::Type::AuthenticationKey)
        .unwrap_or_else(|err| panic!("error getting object info: {err}"));

    assert_eq!(object_info.capabilities, Capability::all());
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, object::Type::AuthenticationKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(&object_info.label.to_string(), TEST_KEY_LABEL);
}

/// The key material really changes: the new key authenticates and the old one
/// stops working.
///
/// Without this, a `change_authentication_key` that silently did nothing would
/// still pass the metadata assertions above.
#[test]
fn change_authentication_key_replaces_key_material() {
    let connector = provision();

    let mut client = yubihsm::Client::open(
        connector.clone(),
        yubihsm::Credentials::from_password(TEST_KEY_ID, OLD_PASSWORD),
        true,
    )
    .unwrap_or_else(|err| panic!("error opening session with original key: {err}"));

    client
        .change_authentication_key(
            TEST_KEY_ID,
            authentication::Algorithm::YubicoAes,
            authentication::Key::derive_from_password(NEW_PASSWORD),
        )
        .unwrap_or_else(|err| panic!("error changing auth key: {err}"));

    // The new key must authenticate.
    yubihsm::Client::open(
        connector.clone(),
        yubihsm::Credentials::from_password(TEST_KEY_ID, NEW_PASSWORD),
        true,
    )
    .unwrap_or_else(|err| panic!("new key should authenticate, got: {err}"));

    // The old key must not.
    assert!(
        yubihsm::Client::open(
            connector.clone(),
            yubihsm::Credentials::from_password(TEST_KEY_ID, OLD_PASSWORD),
            true,
        )
        .is_err(),
        "old key must no longer authenticate after being changed"
    );
}

/// The device only allows changing the authentication key that established the
/// current session. Attempting to change any other key is rejected.
#[test]
fn change_authentication_key_rejects_other_keys() {
    let connector = provision();

    // Authenticated as the default admin key, not as `TEST_KEY_ID`.
    let mut admin = yubihsm::Client::open(connector.clone(), Default::default(), true)
        .unwrap_or_else(|err| panic!("error opening admin session: {err}"));

    assert!(
        admin
            .change_authentication_key(
                TEST_KEY_ID,
                authentication::Algorithm::YubicoAes,
                authentication::Key::derive_from_password(NEW_PASSWORD),
            )
            .is_err(),
        "changing an authentication key other than the session's must be rejected"
    );

    // The untouched key must still authenticate with its original password.
    yubihsm::Client::open(
        connector.clone(),
        yubihsm::Credentials::from_password(TEST_KEY_ID, OLD_PASSWORD),
        true,
    )
    .unwrap_or_else(|err| panic!("untouched key should still authenticate, got: {err}"));
}
