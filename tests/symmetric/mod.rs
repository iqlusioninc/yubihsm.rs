use cipher::{
    block_padding::{NoPadding, Padding, Pkcs7},
    consts::U16,
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, BlockSizeUser,
    InnerIvInit, Iv, Key, KeyInit, KeySizeUser,
};
use common::{typenum::Unsigned, Generate, KeyIvInit};
use rand::{CryptoRng, Rng};

use yubihsm::{
    object,
    symmetric::{
        cbc::{Decryptor, Encryptor},
        AssociatedHsmSymmetricAlgorithm, HsmKey,
    },
    wrap, Capability, Client,
};

const TEST_CIPHER_KEY_LABEL: &str = "Cipher test key";
const TEST_CIPHER_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

#[test]
fn roundtrip_cbc_test() {
    fn test_roundtrip_inner<
        R: CryptoRng,
        P: Padding,
        C: BlockCipherEncrypt
            + BlockCipherDecrypt
            + KeyInit
            + KeySizeUser
            + BlockSizeUser<BlockSize = U16>,
    >(
        rng: &mut R,
        client: &Client,
        key_id: object::Id,
        key: &Key<C>,
        payload_blocks: usize,
    ) {
        let iv = Iv::<Encryptor>::generate_from_rng(rng);

        let encryptor = Encryptor::inner_iv_init(HsmKey::new(client.clone(), key_id), &iv);
        let oracle_enc = cbc::Encryptor::<C>::new(&key, &iv);

        let mut plaintext =
            vec![0; payload_blocks * <Encryptor as BlockSizeUser>::BlockSize::USIZE];
        rng.fill_bytes(&mut plaintext);

        let ciphertext = encryptor.encrypt_padded_vec::<P>(&plaintext);
        let ciphertext_expected = oracle_enc.encrypt_padded_vec::<P>(&plaintext);

        assert_eq!(ciphertext, ciphertext_expected, "ciphertext mismatch");

        let decryptor = Decryptor::inner_iv_init(HsmKey::new(client.clone(), key_id), &iv);
        let oracle_dec = cbc::Decryptor::<C>::new(&key, &iv);

        let output = decryptor.decrypt_padded_vec::<P>(&ciphertext).unwrap();
        let output_expected = oracle_dec.decrypt_padded_vec::<P>(&ciphertext).unwrap();

        assert_eq!(output, output_expected, "output mismatch");
        assert_eq!(output, plaintext, "output mismatch");
    }
    fn test_roundtrip<
        R: CryptoRng,
        C: BlockCipherEncrypt
            + BlockCipherDecrypt
            + KeyInit
            + KeySizeUser
            + BlockSizeUser<BlockSize = U16>
            + AssociatedHsmSymmetricAlgorithm,
    >(
        rng: &mut R,
        client: &Client,
        payload_blocks: usize,
    ) {
        let key = Key::<C>::generate_from_rng(rng);

        let test_cipher_key_capabilities: Capability =
            Capability::DECRYPT_CBC | Capability::ENCRYPT_CBC;
        let key_id = 123;
        let alg = C::HSM_SYMMETRIC_ALGORITHM;

        let _ = client.delete_object(key_id, yubihsm::object::Type::SymmetricKey);
        client
            .put_symmetric_key(
                key_id,
                TEST_CIPHER_KEY_LABEL.into(),
                TEST_CIPHER_KEY_DOMAINS,
                test_cipher_key_capabilities,
                alg,
                &key,
            )
            .unwrap();

        test_roundtrip_inner::<R, NoPadding, C>(rng, client, key_id, &key, payload_blocks);
        test_roundtrip_inner::<R, Pkcs7, C>(rng, client, key_id, &key, payload_blocks);

        let _ = client.delete_object(key_id, yubihsm::object::Type::SymmetricKey);
    }

    let mut rng = rand::rng();
    let client = crate::get_hsm_client();

    for payload_blocks in [
        0usize, // HSM will reply with an error if block is empty
        1, 2, 10, 16, 123, 124, // Up to 124, the encryptor will use tail_blocks
        125, // At 125 it should use encrypt_par_blocks
        // And after that par_blocks and tail_blocks
        126, 200,
    ] {
        test_roundtrip::<_, aes::Aes128>(&mut rng, &client, payload_blocks);
        test_roundtrip::<_, aes::Aes192>(&mut rng, &client, payload_blocks);
        test_roundtrip::<_, aes::Aes256>(&mut rng, &client, payload_blocks);
    }
}

#[test]
fn generate_symmetric_key() {
    let mut rng = rand::rng();
    let client = crate::get_hsm_client();

    let key_id = 123;
    let test_cipher_key_capabilities: Capability =
        Capability::DECRYPT_CBC | Capability::ENCRYPT_CBC | Capability::EXPORTABLE_UNDER_WRAP;
    let exported_key_type = object::Type::SymmetricKey;

    let _ = client.delete_object(key_id, exported_key_type);
    client
        .generate_symmetric_key(
            key_id,
            TEST_CIPHER_KEY_LABEL.into(),
            TEST_CIPHER_KEY_DOMAINS,
            test_cipher_key_capabilities,
            aes::Aes128::HSM_SYMMETRIC_ALGORITHM,
        )
        .expect("Create a symmetric key");

    let wrap_key = Key::<aes::Aes128>::generate_from_rng(&mut rng);
    let algorithm = wrap::Algorithm::Aes128Ccm;
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();
    let wrap_key_id = 124;
    let _ = client.delete_object(wrap_key_id, yubihsm::object::Type::WrapKey);

    client
        .put_wrap_key(
            wrap_key_id,
            "Wrap key".into(),
            TEST_CIPHER_KEY_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            wrap_key,
        )
        .expect("add a wrap key");

    let wrap_data = client
        .export_wrapped(wrap_key_id, exported_key_type, key_id)
        .unwrap_or_else(|err| panic!("error exporting key: {err}"));

    // Delete the object from the HSM prior to re-importing it
    assert!(client.delete_object(key_id, exported_key_type).is_ok());

    // Decipher the symmetric key
    let wrap_key = wrap::Key::from_bytes(wrap_key_id, &wrap_key).unwrap();

    let plaintext = wrap_data
        .decrypt(&wrap_key)
        .expect("failed to decrypt the wrapped key");

    let symmetric_key = plaintext
        .symmetric::<aes::Aes128>()
        .expect("Object did not contain an Aes128 object");

    let wrap_plaintext = wrap::Plaintext::from_symmetric::<aes::Aes128>(
        algorithm,
        key_id,
        test_cipher_key_capabilities,
        TEST_CIPHER_KEY_DOMAINS,
        TEST_CIPHER_KEY_LABEL.into(),
        &symmetric_key,
    );
    let wrap_data = wrap_plaintext
        .encrypt(&wrap_key)
        .expect("Failed to re-encrypt the wrapped key");

    // Re-import the wrapped key back into the HSM
    client
        .import_wrapped(wrap_key_id, wrap_data)
        .expect("error importing key");

    let mut plaintext = vec![0; 32];
    rng.fill_bytes(&mut plaintext);

    let iv = Iv::<Encryptor>::generate_from_rng(&mut rng);

    let encryptor = Encryptor::inner_iv_init(HsmKey::new(client.clone(), key_id), &iv);
    let oracle_enc = cbc::Encryptor::<aes::Aes128>::new(&symmetric_key, &iv);

    let ciphertext = encryptor.encrypt_padded_vec::<NoPadding>(&plaintext);
    let ciphertext_expected = oracle_enc.encrypt_padded_vec::<NoPadding>(&plaintext);

    assert_eq!(ciphertext, ciphertext_expected, "ciphertext mismatch");
}
