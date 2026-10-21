/// Get device information
#[test]
fn device_info_test() {
    let client = crate::get_hsm_client();

    let device_info = client
        .device_info()
        .unwrap_or_else(|err| panic!("error getting device info: {err}"));

    // This should always be 2. The minor and patch versions will vary
    // depending on the specific YubiHSM 2 model.
    assert_eq!(device_info.major_version, 2);
}

/// Get device information without opening a session
#[test]
fn unauthenticated_device_info_test() {
    let device_info = crate::HSM_CONNECTOR
        .device_info()
        .unwrap_or_else(|err| panic!("error getting unauthenticated device info: {err}"));

    assert_eq!(device_info.major_version, 2);
    assert!(device_info.log_store_capacity > 0);

    // The unauthenticated answer should agree with the session's. (It is not
    // authenticated, so a mismatch means something on the path is rewriting it.)
    let session_info = crate::get_hsm_client().device_info().unwrap();
    assert_eq!(device_info.serial_number, session_info.serial_number);
    assert_eq!(device_info.major_version, session_info.major_version);
}
