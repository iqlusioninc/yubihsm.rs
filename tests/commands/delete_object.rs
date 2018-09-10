use yubihsm::{self, AsymmetricAlgorithm, Capability, ObjectType};

use {generate_asymmetric_key, TEST_KEY_ID};

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
