/// Get random bytes
#[test]
fn get_pseudo_random_test() {
    let client = crate::get_hsm_client();

    let bytes = client
        .get_pseudo_random(32)
        .unwrap_or_else(|err| panic!("error getting random data: {}", err));

    assert_eq!(32, bytes.len());
}
