//! YubiHSM2 setup tests: test declarative provisioning of a YubiHSM2 from scratch

use yubihsm::{
    authentication::{self, Credentials},
    object,
    setup::{Profile, Role},
    Capability, Domain,
};

const ROOT_KEY_ID: object::Id = 1;
const ROOT_KEY_LABEL: &str = "root key";

#[test]
fn setup_test() {
    let root_key = authentication::Key::random();
    let root_role = Role::new(Credentials::new(ROOT_KEY_ID, root_key))
        .authentication_key_label(ROOT_KEY_LABEL)
        .capabilities(Capability::all())
        .domains(Domain::all());

    // TODO: actually test provisioning the profile
    let _profile = Profile::default().roles(vec![root_role]);
}
