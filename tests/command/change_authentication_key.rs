use yubihsm::{authentication, object, Capability};

use crate::{clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL, TEST_MESSAGE};

/// Change an authentication key's key material in the `YubiHSM`
#[test]
fn change_authentication_key() {
    let client = crate::get_hsm_client();
    let algorithm = authentication::Algorithm::YubicoAes;
    let capabilities = Capability::all();
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&client, object::Type::AuthenticationKey);

    // First, put a key so we have something to change
    let original_key = authentication::Key::derive_from_password(TEST_MESSAGE);

    let key_id = client
        .put_authentication_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            original_key,
        )
        .unwrap_or_else(|err| panic!("error putting auth key: {err}"));

    assert_eq!(key_id, TEST_KEY_ID);

    // Now change the key material — metadata should be preserved
    let new_key = authentication::Key::derive_from_password(b"new password");

    let changed_id = client
        .change_authentication_key(TEST_KEY_ID, algorithm, new_key)
        .unwrap_or_else(|err| panic!("error changing auth key: {err}"));

    assert_eq!(changed_id, TEST_KEY_ID);

    // Verify metadata is preserved after change
    let object_info = client
        .get_object_info(TEST_KEY_ID, object::Type::AuthenticationKey)
        .unwrap_or_else(|err| panic!("error getting object info: {err}"));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, object::Type::AuthenticationKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(&object_info.label.to_string(), TEST_KEY_LABEL);
}
