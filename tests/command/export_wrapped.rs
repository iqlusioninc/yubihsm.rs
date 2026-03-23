use crate::{
    clear_test_key_slot, test_vectors::AESCCM_TEST_VECTORS, TEST_DOMAINS, TEST_EXPORTED_KEY_ID,
    TEST_EXPORTED_KEY_LABEL, TEST_KEY_ID, TEST_KEY_LABEL,
};
use base64::Engine as _;
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
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

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
        .unwrap_or_else(|err| panic!("error generating asymmetric key: {err}"));

    let wrap_data = client
        .export_wrapped(TEST_KEY_ID, exported_key_type, TEST_EXPORTED_KEY_ID)
        .unwrap_or_else(|err| panic!("error exporting key: {err}"));

    // Delete the object from the HSM prior to re-importing it
    assert!(client
        .delete_object(TEST_EXPORTED_KEY_ID, exported_key_type)
        .is_ok());

    // Re-import the wrapped key back into the HSM
    let import_response = client
        .import_wrapped(TEST_KEY_ID, wrap_data)
        .unwrap_or_else(|err| panic!("error importing key: {err}"));

    assert_eq!(import_response.object_type, exported_key_type);
    assert_eq!(import_response.object_id, TEST_EXPORTED_KEY_ID);

    let imported_key_info = client
        .get_object_info(TEST_EXPORTED_KEY_ID, exported_key_type)
        .unwrap_or_else(|err| panic!("error getting object info: {err}"));

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

#[test]
fn wrap_key_from_yhw() {
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
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

    assert_eq!(key_id, TEST_KEY_ID);
    const TEST_EXPORTED_KEY_ID: u16 = 13;

    let exported_key_type = object::Type::AsymmetricKey;
    let exported_key_capabilities = Capability::EXPORTABLE_UNDER_WRAP;
    let exported_key_algorithm = asymmetric::Algorithm::Ed25519;

    // file created using yubihsm-shell tool
    let wrapped = base64::prelude::BASE64_STANDARD
        .decode(include_str!("../test_vectors/private-ed25519-seed.yhw").trim())
        .expect("base64 decode to succeed");
    let wrap_data = wrap::Message::from_vec(wrapped).expect("wrap file to be correct");

    // Re-import the wrapped key back into the HSM
    let import_response = client
        .import_wrapped(TEST_KEY_ID, wrap_data)
        .unwrap_or_else(|err| panic!("error importing key: {err}"));

    assert_eq!(import_response.object_type, exported_key_type);
    assert_eq!(import_response.object_id, TEST_EXPORTED_KEY_ID);

    let imported_key_info = client
        .get_object_info(TEST_EXPORTED_KEY_ID, exported_key_type)
        .unwrap_or_else(|err| panic!("error getting object info: {err}"));

    assert_eq!(imported_key_info.capabilities, exported_key_capabilities);
    assert_eq!(imported_key_info.object_id, TEST_EXPORTED_KEY_ID);
    assert_eq!(imported_key_info.object_type, exported_key_type);
    assert_eq!(imported_key_info.algorithm, exported_key_algorithm.into());
    assert_eq!(imported_key_info.origin, object::Origin::Generated);
    assert_eq!(&imported_key_info.label.to_string(), "Signature_Key_Ed_2");
}

#[test]
fn wrap_deserialize() {
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
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

    assert_eq!(key_id, TEST_KEY_ID);

    // Create a key to export
    let exported_key_type = object::Type::AsymmetricKey;
    let exported_key_capabilities = Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP;
    let exported_key_algorithm = asymmetric::Algorithm::EcP256;

    let _ = client.delete_object(TEST_EXPORTED_KEY_ID, exported_key_type);

    client
        .generate_asymmetric_key(
            TEST_EXPORTED_KEY_ID,
            TEST_EXPORTED_KEY_LABEL.into(),
            TEST_DOMAINS,
            exported_key_capabilities,
            exported_key_algorithm,
        )
        .unwrap_or_else(|err| panic!("error generating asymmetric key: {err}"));

    let wrap_data = client
        .export_wrapped(TEST_KEY_ID, exported_key_type, TEST_EXPORTED_KEY_ID)
        .unwrap_or_else(|err| panic!("error exporting key: {err}"));

    let wrap_key = wrap::Key::from_bytes(TEST_KEY_ID, AESCCM_TEST_VECTORS[0].key).unwrap();

    let plaintext = wrap_data
        .decrypt(&wrap_key)
        .expect("failed to decrypt the wrapped key");

    let private_key: p256::SecretKey = plaintext
        .ecdsa()
        .expect("Object did not contain a NistP256 object");
    let public_key: p256::EncodedPoint = private_key.public_key().into();

    assert_eq!(
        client
            .get_public_key(TEST_EXPORTED_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {err}"))
            .ecdsa::<p256::NistP256>()
            .expect("public key was not a NistP256 object"),
        public_key
    );
}
