use yubihsm::{AuthAlg, AuthKey, Capability, ObjectOrigin, ObjectType};

use {clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL, TEST_MESSAGE};

/// Put a new authentication key into the `YubiHSM`
#[test]
fn put_auth_key() {
    let mut client = ::get_hsm_client();
    let algorithm = AuthAlg::YUBICO_AES;
    let capabilities = Capability::all();
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&mut client, ObjectType::AuthKey);

    let new_auth_key = AuthKey::derive_from_password(TEST_MESSAGE);

    let key_id = client
        .put_auth_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            new_auth_key,
        ).unwrap_or_else(|err| panic!("error putting auth key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    let object_info = client
        .get_object_info(TEST_KEY_ID, ObjectType::AuthKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AuthKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}
