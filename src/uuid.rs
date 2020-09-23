//! UUID functionality

use rand_core::{OsRng, RngCore};
pub use uuid::Uuid;
use uuid::{Builder, Variant, Version};

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);

    Builder::from_bytes(bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build()
}
