//! UUID functionality

use rand_core::{OsRng, TryRngCore};
use uuid::Builder;
pub use uuid::Uuid;

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut bytes = [0; 16];
    OsRng.try_fill_bytes(&mut bytes).unwrap();
    Builder::from_random_bytes(bytes).into_uuid()
}
