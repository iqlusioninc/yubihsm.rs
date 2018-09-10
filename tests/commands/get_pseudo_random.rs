use yubihsm;

/// Get random bytes
#[test]
fn get_pseudo_random_test() {
    let mut session = create_session!();

    let bytes = yubihsm::get_pseudo_random(&mut session, 32)
        .unwrap_or_else(|err| panic!("error getting random data: {}", err));

    assert_eq!(32, bytes.len());
}
