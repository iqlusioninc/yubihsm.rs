//! UUID functionality

extern crate uuid as uuid_crate;

pub use uuid_crate::Uuid;

use rand_os::{rand_core::RngCore, OsRng};
use uuid_crate::{Builder, Variant, Version};

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut rng = OsRng::new().unwrap();
    let mut bytes = [0; 16];
    rng.fill_bytes(&mut bytes);

    Builder::from_bytes(bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build()
}
