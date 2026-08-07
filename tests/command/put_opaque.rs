use yubihsm::{object, opaque, wrap, Capability};

use crate::{
    clear_test_key_slot, test_vectors::AESCCM_TEST_VECTORS, TEST_DOMAINS, TEST_EXPORTED_KEY_ID,
    TEST_EXPORTED_KEY_LABEL, TEST_KEY_ID, TEST_KEY_LABEL, TEST_MESSAGE,
};

/// Put an opaque object and read it back
#[test]
fn opaque_object_test() {
    let client = crate::get_hsm_client();

    clear_test_key_slot(&client, object::Type::Opaque);

    let object_id = client
        .put_opaque(
            TEST_KEY_ID,
            TEST_KEY_LABEL
                .parse()
                .expect("TEST_KEY_LABEL to be shorter than or equal to 40 bytes"),
            TEST_DOMAINS,
            Capability::default(),
            opaque::Algorithm::Data,
            TEST_MESSAGE,
        )
        .unwrap_or_else(|err| panic!("error putting opaque object: {err}"));

    assert_eq!(object_id, TEST_KEY_ID);

    let opaque_data = client
        .get_opaque(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting opaque object: {err}"));

    assert_eq!(opaque_data, TEST_MESSAGE);
}

/// Put an opaque object and export it back out
#[test]
fn opaque_object_export_test() {
    let client = crate::get_hsm_client();

    clear_test_key_slot(&client, object::Type::Opaque);
    let _ = client.delete_object(TEST_EXPORTED_KEY_ID, object::Type::Opaque);
    let _ = client.delete_object(TEST_KEY_ID, object::Type::WrapKey);

    let _object_id = client
        .put_opaque(
            TEST_EXPORTED_KEY_ID,
            TEST_EXPORTED_KEY_LABEL
                .parse()
                .expect("TEST_EXPORTED_KEY_LABEL to be shorter than or equal to 40 bytes"),
            TEST_DOMAINS,
            Capability::EXPORTABLE_UNDER_WRAP,
            opaque::Algorithm::Data,
            TEST_MESSAGE,
        )
        .unwrap_or_else(|err| panic!("error putting opaque object: {err}"));

    let algorithm = wrap::Algorithm::Aes128Ccm;
    let delegated_capabilities = Capability::all();
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let _export_key_id = client
        .put_wrap_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL
                .parse()
                .expect("TEST_KEY_LABEL to be shorter than or equal to 40 bytes"),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            AESCCM_TEST_VECTORS[0].key,
        )
        .unwrap_or_else(|err| panic!("error adding wrap key: {err}"));

    let wrap_key = wrap::Key::from_bytes(TEST_KEY_ID, AESCCM_TEST_VECTORS[0].key).unwrap();
    let exported_key_type = object::Type::Opaque;
    let wrap_data = client
        .export_wrapped(TEST_KEY_ID, exported_key_type, TEST_EXPORTED_KEY_ID)
        .unwrap_or_else(|err| panic!("error exporting opaque: {err}"));
    let plaintext = wrap_data
        .decrypt(&wrap_key)
        .expect("failed to decrypt the wrapped data");

    assert_eq!(plaintext.data, TEST_MESSAGE);
    let message = plaintext
        .opaque_data()
        .expect("Content should be an opaque type");

    assert_eq!(message.as_ref(), TEST_MESSAGE);

    let plaintext = wrap::Plaintext::from_opaque_data(
        algorithm,
        opaque::Algorithm::Data,
        TEST_EXPORTED_KEY_ID,
        Capability::default(),
        TEST_DOMAINS,
        TEST_EXPORTED_KEY_LABEL
            .parse()
            .expect("TEST_EXPORTED_KEY_LABEL to be shorter than or equal to 40 bytes"),
        &message,
    )
    .expect("Failed to wrap the opaque payload");

    let _ = client.delete_object(TEST_EXPORTED_KEY_ID, object::Type::Opaque);
    let ciphertext = plaintext
        .encrypt(&wrap_key)
        .expect("failed to encrypt the wrapped data");

    let handle = client
        .import_wrapped(TEST_KEY_ID, ciphertext)
        .unwrap_or_else(|err| panic!("error importing opaque: {err}"));
    assert_eq!(handle.object_id, TEST_EXPORTED_KEY_ID);

    let opaque_data = client
        .get_opaque(TEST_EXPORTED_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting opaque object: {err}"));

    assert_eq!(opaque_data, TEST_MESSAGE);
}

/// A `Plaintext` built for an X.509 certificate must be readable as one.
///
/// `from_opaque_data` previously hardcoded `opaque::Algorithm::Data`, so a
/// certificate opaque could never be constructed even though
/// `Plaintext::opaque_certificate` exists to read them back — the writer and
/// the reader disagreed.
#[cfg(feature = "x509-cert")]
#[test]
fn opaque_certificate_round_trips_the_algorithm() {
    let der = b"not a real certificate, but the algorithm gate is what matters";

    let plaintext = wrap::Plaintext::from_opaque_data(
        wrap::Algorithm::Aes128Ccm,
        opaque::Algorithm::X509Certificate,
        TEST_EXPORTED_KEY_ID,
        Capability::default(),
        TEST_DOMAINS,
        TEST_EXPORTED_KEY_LABEL
            .parse()
            .expect("TEST_EXPORTED_KEY_LABEL to be shorter than or equal to 40 bytes"),
        der,
    )
    .expect("building an opaque certificate plaintext");

    // The reader only yields a value when the object algorithm matches.
    assert!(
        plaintext.opaque_certificate().is_some(),
        "an X509Certificate opaque must be reachable via opaque_certificate()"
    );

    // ...and it must not masquerade as plain data.
    assert!(
        plaintext.opaque_data().is_none(),
        "an X509Certificate opaque must not read back as Data"
    );
}
