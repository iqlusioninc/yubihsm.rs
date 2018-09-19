use yubihsm::{self, Capability, ObjectType, OpaqueAlg};

use {clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL, TEST_MESSAGE};

/// Put an opaque object and read it back
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
        OpaqueAlg::DATA,
        TEST_MESSAGE,
    ).unwrap_or_else(|err| panic!("error putting opaque object: {}", err));

    assert_eq!(object_id, TEST_KEY_ID);

    let opaque_data = yubihsm::get_opaque(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting opaque object: {}", err));

    assert_eq!(opaque_data, TEST_MESSAGE);
}
