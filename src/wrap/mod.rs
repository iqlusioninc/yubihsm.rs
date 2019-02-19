//! "Wrapping" support: YubiHSM2 key/object encryption for backups and
//! importing existing keys to other derivces.

mod message;
mod nonce;

pub use self::{message::Message, nonce::Nonce};
