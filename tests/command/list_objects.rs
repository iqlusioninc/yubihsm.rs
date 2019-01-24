use yubihsm::{client::Filter, AsymmetricAlg, Capability, ObjectType};

use crate::{generate_asymmetric_key, TEST_KEY_ID};

/// List the objects in the YubiHSM2
#[test]
fn list_objects_test() {
    let mut client = crate::get_hsm_client();

    generate_asymmetric_key(&mut client, AsymmetricAlg::Ed25519, Capability::SIGN_EDDSA);

    let objects = client
        .list_objects(&[])
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Look for the asymmetric key we just generated
    assert!(objects
        .iter()
        .find(|i| i.object_id == TEST_KEY_ID && i.object_type == ObjectType::AsymmetricKey)
        .is_some());
}

/// Filter objects in the HSM by their type
#[test]
fn list_objects_with_filter() {
    let mut client = crate::get_hsm_client();

    let objects = client
        .list_objects(&[Filter::Type(ObjectType::AuthenticationKey)])
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    assert!(objects
        .iter()
        .all(|obj| obj.object_type == ObjectType::AuthenticationKey));
}
