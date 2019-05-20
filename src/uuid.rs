//! UUID functionality

use getrandom::getrandom;
pub use uuid::Uuid;
use uuid::{Builder, Variant, Version};

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut bytes = [0; 16];
    getrandom(&mut bytes).expect("RNG failure!");

    Builder::from_bytes(bytes)
        .set_variant(Variant::RFC4122)
        .set_version(Version::Random)
        .build()
}
