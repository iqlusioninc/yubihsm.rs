use crate::DEFAULT_AUTHENTICATION_KEY_LABEL;
use yubihsm::{
    authentication::{self, DEFAULT_AUTHENTICATION_KEY_ID},
    object, Capability, Domain,
};

/// Get object info on default auth key
#[test]
fn default_authkey_test() {
    let client = crate::get_hsm_client();

    let object_info = client
        .get_object_info(
            DEFAULT_AUTHENTICATION_KEY_ID,
            object::Type::AuthenticationKey,
        )
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, Capability::all());
    assert_eq!(object_info.object_id, DEFAULT_AUTHENTICATION_KEY_ID);
    assert_eq!(object_info.domains, Domain::all());
    assert_eq!(object_info.object_type, object::Type::AuthenticationKey);
    assert_eq!(
        object_info.algorithm,
        authentication::Algorithm::YubicoAes.into()
    );
    assert_eq!(object_info.origin, object::Origin::Imported);
    assert_eq!(
        &object_info.label.to_string(),
        DEFAULT_AUTHENTICATION_KEY_LABEL
    );
}
