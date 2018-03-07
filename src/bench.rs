use test::Bencher;

use {Algorithm, Capabilities, Connector, Domains, ObjectId, ObjectType};

const YUBIHSM_ADDR: &str = "http://127.0.0.1:12345";
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;
const DEFAULT_PASSWORD: &str = "password";
const EXAMPLE_MESSAGE: &[u8] = b"";
const TEST_KEY_ID: ObjectId = 100;
const TEST_KEY_LABEL: &str = "yubihsm.rs benchmarking key";
const TEST_CAPABILITIES: Capabilities = Capabilities::ASYMMETRIC_SIGN_EDDSA;
const TEST_DOMAINS: Domains = Domains::DOMAIN_1;

#[bench]
fn ed25519_benchmark(b: &mut Bencher) {
    let conn = Connector::open(YUBIHSM_ADDR).unwrap();
    let mut session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap();

    // Delete the key in TEST_KEY_ID slot it exists
    let _ = session.delete_object(TEST_KEY_ID, ObjectType::Asymmetric);

    // Create a new key for testing
    session
        .generate_asymmetric_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            TEST_CAPABILITIES,
            Algorithm::EC_ED25519,
        )
        .unwrap();

    b.iter(|| {
        session
            .sign_data_eddsa(TEST_KEY_ID, EXAMPLE_MESSAGE)
            .unwrap()
    });
}
