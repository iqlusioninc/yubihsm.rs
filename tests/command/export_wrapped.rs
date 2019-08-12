use crate::{
    clear_test_key_slot, test_vectors::AESCCM_TEST_VECTORS, TEST_DOMAINS, TEST_EXPORTED_KEY_ID,
    TEST_EXPORTED_KEY_LABEL, TEST_KEY_ID, TEST_KEY_LABEL,
};
use yubihsm::{asymmetric, object, wrap, Capability};

/// Test wrap key workflow using randomly generated keys
// TODO: test against RFC 3610 vectors
#[test]
fn wrap_key_test() {
    let client = crate::get_hsm_client();
    let algorithm = wrap::Algorithm::Aes128Ccm;
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&client, object::Type::WrapKey);

    let key_id = client
        .put_wrap_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            AESCCM_TEST_VECTORS[0].key,
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    // Create a key to export
    let exported_key_type = object::Type::AsymmetricKey;
    let exported_key_capabilities = Capability::SIGN_EDDSA | Capability::EXPORTABLE_UNDER_WRAP;
    let exported_key_algorithm = asymmetric::Algorithm::Ed25519;

    let _ = client.delete_object(TEST_EXPORTED_KEY_ID, exported_key_type);

    client
        .generate_asymmetric_key(
            TEST_EXPORTED_KEY_ID,
            TEST_EXPORTED_KEY_LABEL.into(),
            TEST_DOMAINS,
            exported_key_capabilities,
            exported_key_algorithm,
        )
        .unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    let wrap_data = client
        .export_wrapped(TEST_KEY_ID, exported_key_type, TEST_EXPORTED_KEY_ID)
        .unwrap_or_else(|err| panic!("error exporting key: {}", err));

    // Delete the object from the HSM prior to re-importing it
    assert!(client
        .delete_object(TEST_EXPORTED_KEY_ID, exported_key_type)
        .is_ok());

    // Re-import the wrapped key back into the HSM
    let import_response = client
        .import_wrapped(TEST_KEY_ID, wrap_data)
        .unwrap_or_else(|err| panic!("error importing key: {}", err));

    assert_eq!(import_response.object_type, exported_key_type);
    assert_eq!(import_response.object_id, TEST_EXPORTED_KEY_ID);

    let imported_key_info = client
        .get_object_info(TEST_EXPORTED_KEY_ID, exported_key_type)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(imported_key_info.capabilities, exported_key_capabilities);
    assert_eq!(imported_key_info.object_id, TEST_EXPORTED_KEY_ID);
    assert_eq!(imported_key_info.domains, TEST_DOMAINS);
    assert_eq!(imported_key_info.object_type, exported_key_type);
    assert_eq!(imported_key_info.algorithm, exported_key_algorithm.into());
    assert_eq!(imported_key_info.origin, object::Origin::WrappedGenerated);
    assert_eq!(
        &imported_key_info.label.to_string(),
        TEST_EXPORTED_KEY_LABEL
    );
}
