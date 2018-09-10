use yubihsm::credentials::DEFAULT_AUTH_KEY_ID;
use yubihsm::{self, AuthAlgorithm, Capability, Domain, ObjectOrigin, ObjectType};

use DEFAULT_AUTH_KEY_LABEL;

/// Get object info on default auth key
#[test]
fn default_authkey_test() {
    let mut session = create_session!();

    let object_info =
        yubihsm::get_object_info(&mut session, DEFAULT_AUTH_KEY_ID, ObjectType::AuthKey)
            .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, Capability::all());
    assert_eq!(object_info.object_id, DEFAULT_AUTH_KEY_ID);
    assert_eq!(object_info.domains, Domain::all());
    assert_eq!(object_info.object_type, ObjectType::AuthKey);
    assert_eq!(object_info.algorithm, AuthAlgorithm::YUBICO_AES_AUTH.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(
        &object_info.label.to_string().unwrap(),
        DEFAULT_AUTH_KEY_LABEL
    );
}
