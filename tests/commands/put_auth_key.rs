use yubihsm::{self, AuthAlgorithm, AuthKey, Capability, ObjectOrigin, ObjectType};

use {clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL, TEST_MESSAGE};

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
