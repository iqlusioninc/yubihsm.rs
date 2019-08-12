use crate::{
    clear_test_key_slot, object, test_vectors::HMAC_SHA256_TEST_VECTORS, TEST_DOMAINS, TEST_KEY_ID,
    TEST_KEY_LABEL,
};
use yubihsm::{hmac, Capability};

/// Test HMAC against RFC 4231 test vectors
#[test]
fn hmac_test_vectors() {
    let client = crate::get_hsm_client();
    let algorithm = hmac::Algorithm::Sha256;
    let capabilities = Capability::SIGN_HMAC | Capability::VERIFY_HMAC;

    for vector in HMAC_SHA256_TEST_VECTORS {
        clear_test_key_slot(&client, object::Type::HmacKey);

        let key_id = client
            .put_hmac_key(
                TEST_KEY_ID,
                TEST_KEY_LABEL.into(),
                TEST_DOMAINS,
                capabilities,
                algorithm,
                vector.key,
            )
            .unwrap_or_else(|err| panic!("error putting HMAC key: {}", err));

        assert_eq!(key_id, TEST_KEY_ID);

        let tag = client
            .sign_hmac(TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error computing HMAC of data: {}", err));

        assert_eq!(tag.as_ref(), vector.tag);

        assert!(client
            .verify_hmac(TEST_KEY_ID, vector.msg, vector.tag)
            .is_ok());

        let mut bad_tag = Vec::from(vector.tag);
        bad_tag[0] ^= 1;

        assert!(client
            .verify_hmac(TEST_KEY_ID, vector.msg, bad_tag)
            .is_err());
    }
}
