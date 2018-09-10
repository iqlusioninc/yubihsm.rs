use yubihsm::{self, AsymmetricAlgorithm, Capability, ObjectOrigin, ObjectType};

use {generate_asymmetric_key, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};

/// Generate an Ed25519 key
#[test]
fn ed25519_key_test() {
    let mut session = create_session!();

    let algorithm = AsymmetricAlgorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    generate_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info =
        yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Generate a NIST P-256 key
#[test]
fn nistp256_key_test() {
    let mut session = create_session!();
    let algorithm = AsymmetricAlgorithm::EC_P256;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    generate_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info =
        yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::AsymmetricKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}
