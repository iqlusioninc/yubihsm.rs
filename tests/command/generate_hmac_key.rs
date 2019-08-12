use crate::{clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};
use yubihsm::{hmac, object, Capability};

/// Generate an HMAC key
#[test]
fn hmac_key_test() {
    let client = crate::get_hsm_client();

    let algorithm = hmac::Algorithm::Sha256;
    let capabilities = Capability::SIGN_HMAC | Capability::VERIFY_HMAC;

    clear_test_key_slot(&client, object::Type::HmacKey);

    let key_id = client
        .generate_hmac_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            algorithm,
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    let object_info = client
        .get_object_info(TEST_KEY_ID, object::Type::HmacKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.object_id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, object::Type::HmacKey);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, object::Origin::Generated);
    assert_eq!(&object_info.label.to_string(), TEST_KEY_LABEL);
}
