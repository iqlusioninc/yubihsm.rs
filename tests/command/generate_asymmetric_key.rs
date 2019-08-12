use crate::{generate_asymmetric_key, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};
use yubihsm::{asymmetric, object, Capability};

/// Generate an Ed25519 key
#[test]
fn ed25519_key_test() {
    let client = crate::get_hsm_client();

    let algorithm = asymmetric::Algorithm::Ed25519;
    let capabilities = Capability::SIGN_EDDSA;

    generate_asymmetric_key(&client, algorithm, capabilities);

    let object_info = client
        .get_object_info(TEST_KEY_ID, object::Type::AsymmetricKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, object::Type::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, object::Origin::Generated);
    assert_eq!(&object_info.label.to_string(), TEST_KEY_LABEL);
}

/// Generate a NIST P-256 key
#[cfg(not(feature = "mockhsm"))]
#[test]
fn nistp256_key_test() {
    let client = crate::get_hsm_client();
    let algorithm = asymmetric::Algorithm::EcP256;
    let capabilities = Capability::SIGN_EDDSA;

    generate_asymmetric_key(&client, algorithm, capabilities);

    let object_info = client
        .get_object_info(TEST_KEY_ID, object::Type::AsymmetricKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, object::Type::AsymmetricKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, object::Origin::Generated);
    assert_eq!(&object_info.label.to_string(), TEST_KEY_LABEL);
}
