/// Reset the YubiHSM2 to a factory default state
#[test]
fn reset_test() {
    let mut client = crate::get_hsm_client();
    client.reset_device().unwrap();
}
