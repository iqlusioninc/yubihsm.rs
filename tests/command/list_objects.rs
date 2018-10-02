use yubihsm::{AsymmetricAlg, Capability, ObjectType};

use {generate_asymmetric_key, TEST_KEY_ID};

/// List the objects in the YubiHSM2
#[test]
fn list_objects_test() {
    let mut client = ::get_hsm_client();

    generate_asymmetric_key(
        &mut client,
        AsymmetricAlg::Ed25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let objects = client
        .list_objects()
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Look for the asymmetric key we just generated
    assert!(
        objects
            .iter()
            .find(|i| i.object_id == TEST_KEY_ID && i.object_type == ObjectType::AsymmetricKey)
            .is_some()
    );
}
