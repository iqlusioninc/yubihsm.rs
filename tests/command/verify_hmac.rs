use yubihsm::{Capability, HmacAlg, ObjectType};

use crate::test_vectors::HMAC_SHA256_TEST_VECTORS;
use crate::{clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};

/// Test HMAC against RFC 4231 test vectors
#[test]
fn hmac_test_vectors() {
    let mut client = crate::get_hsm_client();
    let algorithm = HmacAlg::SHA256;
    let capabilities = Capability::HMAC_DATA | Capability::HMAC_VERIFY;

    for vector in HMAC_SHA256_TEST_VECTORS {
        clear_test_key_slot(&mut client, ObjectType::HMACKey);

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
            .hmac(TEST_KEY_ID, vector.msg)
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
