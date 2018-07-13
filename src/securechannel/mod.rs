//! Implementation of the GlobalPlatform Secure Channel Protocol "03"
//!
//! See GPC_SPE_014: GlobalPlatform Card Technology Secure Channel Protocol '03' at:
//! <https://www.globalplatform.org/specificationscard.asp>
//!
//! SCP03 provides an encrypted channel using symmetric encryption alone.
//! AES-128-CBC is used for encryption, and AES-128-CMAC for authentication.
//!
//! While SCP03 is a multipurpose protocol, this implementation has been
//! written with the specific intention of communicating with Yubico's
//! YubiHSM2 devices and therefore omits certain features (e.g. additional
//! key sizes besides 128-bit) which are not relevant to the YubiHSM2 use case.
//!
//! It also follows the APDU format as described in Yubico's YubiHSM2
//! documentation as opposed to the one specified in GPC_SPE_014.
//!
//! For more information on the YubiHSM2 command format, see:
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

#![allow(unknown_lints, doc_markdown)]

#[macro_use]
mod error;

mod challenge;
mod channel;
mod command_message;
mod context;
mod cryptogram;
mod kdf;
mod mac;
mod response_message;

/// AES key size in bytes. SCP03 theoretically supports other key sizes, but
/// since this crate is somewhat specialized to the `YubiHSM2` (at least for now)
/// we hardcode to 128-bit for simplicity.
pub const KEY_SIZE: usize = 16;

/// Maximum size of the message buffer
pub const MAX_MSG_SIZE: usize = 2048;

pub use self::challenge::{Challenge, CHALLENGE_SIZE};
pub(crate) use self::channel::Channel;
pub use self::channel::Id as SessionId;
pub(crate) use self::command_message::CommandMessage;
pub use self::context::{Context, CONTEXT_SIZE};
pub use self::cryptogram::{Cryptogram, CRYPTOGRAM_SIZE};
pub use self::error::{SecureChannelError, SecureChannelErrorKind};
pub(crate) use self::mac::{Mac, MAC_SIZE};
pub(crate) use self::response_message::{ResponseCode, ResponseMessage};
