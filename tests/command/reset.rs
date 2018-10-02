/// Reset the YubiHSM2 to a factory default state
#[test]
fn reset_test() {
    let mut client = ::get_hsm_client();
    client.reset().unwrap();
}
