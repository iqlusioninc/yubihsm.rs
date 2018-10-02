use yubihsm::{AsymmetricAlg, Capability, ObjectType};
use {generate_asymmetric_key, TEST_KEY_ID};

/// Delete an object in the YubiHSM2
#[test]
fn delete_object_test() {
    let mut client = ::get_hsm_client();

    generate_asymmetric_key(
        &mut client,
        AsymmetricAlg::Ed25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    // The first request to delete should succeed because the object exists
    assert!(
        client
            .delete_object(TEST_KEY_ID, ObjectType::AsymmetricKey)
            .is_ok()
    );

    // The second request to delete should fail because it's already deleted
    assert!(
        client
            .delete_object(TEST_KEY_ID, ObjectType::AsymmetricKey)
            .is_err()
    );
}
