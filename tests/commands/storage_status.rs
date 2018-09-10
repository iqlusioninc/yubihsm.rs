use yubihsm;

/// Get stats about currently free storage
#[test]
fn storage_status_test() {
    let mut session = create_session!();

    let response = yubihsm::storage_status(&mut session)
        .unwrap_or_else(|err| panic!("error getting storage status: {}", err));

    // TODO: these will probably have to change if Yubico releases new models
    assert_eq!(response.total_records, 256);
    assert_eq!(response.total_pages, 1024);
    assert_eq!(response.page_size, 126);
}
