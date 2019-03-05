use TEST_MESSAGE;

/// Send a simple echo request
#[test]
fn echo_test() {
    let client = crate::create_client();

    let echo_response = client.echo(TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(TEST_MESSAGE, echo_response.as_slice());
}
