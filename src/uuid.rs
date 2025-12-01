//! UUID functionality

use rand_core::RngCore;
use uuid::Builder;
pub use uuid::Uuid;

/// Create a random UUID
pub fn new_v4() -> Uuid {
    let mut bytes = [0; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut bytes);
    Builder::from_random_bytes(bytes).into_uuid()
}
