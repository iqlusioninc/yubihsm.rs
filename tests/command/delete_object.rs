use crate::{generate_asymmetric_key, TEST_KEY_ID};
use yubihsm::{asymmetric, object, Capability};

/// Delete an object in the YubiHSM 2
#[test]
fn delete_object_test() {
    let client = crate::get_hsm_client();

    generate_asymmetric_key(
        &client,
        asymmetric::Algorithm::Ed25519,
        Capability::SIGN_EDDSA,
    );

    // The first request to delete should succeed because the object exists
    assert!(client
        .delete_object(TEST_KEY_ID, object::Type::AsymmetricKey)
        .is_ok());

    // The second request to delete should fail because it's already deleted
    assert!(client
        .delete_object(TEST_KEY_ID, object::Type::AsymmetricKey)
        .is_err());
}
