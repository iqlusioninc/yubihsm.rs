use yubihsm;

use TEST_MESSAGE;

/// Send a simple echo request
#[test]
fn echo_test() {
    let mut session = create_session!();

    let echo_response = yubihsm::echo(&mut session, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(TEST_MESSAGE, echo_response.as_slice());
}
