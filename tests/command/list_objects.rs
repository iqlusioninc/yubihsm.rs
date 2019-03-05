use crate::{generate_asymmetric_key, TEST_KEY_ID};
use yubihsm::{asymmetric, object, Capability};

/// List the objects in the YubiHSM 2
#[test]
fn list_objects_test() {
    let client = crate::get_hsm_client();

    generate_asymmetric_key(
        &client,
        asymmetric::Algorithm::Ed25519,
        Capability::SIGN_EDDSA,
    );

    let objects = client
        .list_objects(&[])
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Look for the asymmetric key we just generated
    assert!(objects
        .iter()
        .find(|i| i.object_id == TEST_KEY_ID && i.object_type == object::Type::AsymmetricKey)
        .is_some());
}

/// Filter objects in the HSM by their type
#[test]
fn list_objects_with_filter() {
    let client = crate::get_hsm_client();

    let objects = client
        .list_objects(&[object::Filter::Type(object::Type::AuthenticationKey)])
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    assert!(objects
        .iter()
        .all(|obj| obj.object_type == object::Type::AuthenticationKey));
}
