/// Get stats about currently free storage
#[test]
fn storage_status_test() {
    let mut client = ::get_hsm_client();

    let response = client
        .storage_status()
        .unwrap_or_else(|err| panic!("error getting storage status: {}", err));

    // TODO: these will probably have to change if Yubico releases new models
    assert_eq!(response.total_records, 256);
    assert_eq!(response.total_pages, 1024);
    assert_eq!(response.page_size, 126);
}
