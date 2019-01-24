use yubihsm::credentials::DEFAULT_AUTH_KEY_ID;
use yubihsm::{AuthAlg, Capability, Domain, ObjectOrigin, ObjectType};

use crate::DEFAULT_AUTH_KEY_LABEL;

/// Get object info on default auth key
#[test]
fn default_authkey_test() {
    let mut client = crate::get_hsm_client();

    let object_info = client
        .get_object_info(DEFAULT_AUTH_KEY_ID, ObjectType::AuthKey)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, Capability::all());
    assert_eq!(object_info.object_id, DEFAULT_AUTH_KEY_ID);
    assert_eq!(object_info.domains, Domain::all());
    assert_eq!(object_info.object_type, ObjectType::AuthKey);
    assert_eq!(object_info.algorithm, AuthAlg::YUBICO_AES.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(
        &object_info.label.to_string().unwrap(),
        DEFAULT_AUTH_KEY_LABEL
    );
}
