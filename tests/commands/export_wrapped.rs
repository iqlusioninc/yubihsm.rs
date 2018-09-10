use yubihsm::{self, AsymmetricAlgorithm, Capability, ObjectOrigin, ObjectType, WrapAlgorithm};

use test_vectors::AESCCM_TEST_VECTORS;
use {
    clear_test_key_slot, TEST_DOMAINS, TEST_EXPORTED_KEY_ID, TEST_EXPORTED_KEY_LABEL, TEST_KEY_ID,
    TEST_KEY_LABEL,
};

/// Test wrap key workflow using randomly generated keys
// TODO: test against RFC 3610 vectors
#[test]
fn wrap_key_test() {
    let mut session = create_session!();
    let algorithm = WrapAlgorithm::AES128_CCM_WRAP;
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();

    clear_test_key_slot(&mut session, ObjectType::WrapKey);

    let key_id = yubihsm::put_wrap_key(
        &mut session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        delegated_capabilities,
        algorithm,
        AESCCM_TEST_VECTORS[0].key,
    ).unwrap_or_else(|err| panic!("error generating wrap key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);

    // Create a key to export
    let exported_key_type = ObjectType::AsymmetricKey;
    let exported_key_capabilities =
        Capability::ASYMMETRIC_SIGN_EDDSA | Capability::EXPORT_UNDER_WRAP;
    let exported_key_algorithm = AsymmetricAlgorithm::EC_ED25519;

    let _ = yubihsm::delete_object(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type);
    yubihsm::generate_asymmetric_key(
        &mut session,
        TEST_EXPORTED_KEY_ID,
        TEST_EXPORTED_KEY_LABEL.into(),
        TEST_DOMAINS,
        exported_key_capabilities,
        exported_key_algorithm,
    ).unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    let wrap_data = yubihsm::export_wrapped(
        &mut session,
        TEST_KEY_ID,
        exported_key_type,
        TEST_EXPORTED_KEY_ID,
    ).unwrap_or_else(|err| panic!("error exporting key: {}", err));

    // Delete the object from the HSM prior to re-importing it
    assert!(yubihsm::delete_object(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type).is_ok());

    // Re-import the wrapped key back into the HSM
    let import_response = yubihsm::import_wrapped(&mut session, TEST_KEY_ID, wrap_data)
        .unwrap_or_else(|err| panic!("error importing key: {}", err));

    assert_eq!(import_response.object_type, exported_key_type);
    assert_eq!(import_response.object_id, TEST_EXPORTED_KEY_ID);

    let imported_key_info =
        yubihsm::get_object_info(&mut session, TEST_EXPORTED_KEY_ID, exported_key_type)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(imported_key_info.capabilities, exported_key_capabilities);
    assert_eq!(imported_key_info.object_id, TEST_EXPORTED_KEY_ID);
    assert_eq!(imported_key_info.domains, TEST_DOMAINS);
    assert_eq!(imported_key_info.object_type, exported_key_type);
    assert_eq!(imported_key_info.algorithm, exported_key_algorithm.into());
    assert_eq!(imported_key_info.origin, ObjectOrigin::WrappedGenerated);
    assert_eq!(
        &imported_key_info.label.to_string().unwrap(),
        TEST_EXPORTED_KEY_LABEL
    );
}
