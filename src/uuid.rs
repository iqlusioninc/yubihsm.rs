//! UUID functionality

use rand_core::{OsRng, RngCore};
use uuid::Builder;
pub use uuid::Uuid;

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    Builder::from_random_bytes(bytes).into_uuid()
}
