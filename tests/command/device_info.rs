/// Get device information
#[test]
fn device_info_test() {
    let mut client = crate::get_hsm_client();

    let device_info = client
        .device_info()
        .unwrap_or_else(|err| panic!("error getting device info: {}", err));

    // This should always be 2. The minor and patch versions will vary
    // depending on the specific YubiHSM2 model.
    assert_eq!(device_info.major_version, 2);
}
