use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use securechannel::CommandMessage;
pub(crate) use securechannel::CommandType;
#[cfg(feature = "mockhsm")]
use securechannel::ResponseMessage;
use serializers::serialize;

pub mod blink;
pub(crate) mod create_session;
pub mod delete_object;
pub mod echo;
pub mod generate_asymmetric_key;
pub mod get_device_info;
pub mod get_logs;
pub mod get_object_info;
pub mod get_pubkey;
pub mod list_objects;
pub mod sign_ecdsa;
pub mod sign_eddsa;

// Import command functions from all submodules
pub use self::blink::*;
pub(crate) use self::create_session::*;
pub use self::delete_object::*;
pub use self::echo::*;
pub use self::generate_asymmetric_key::*;
pub use self::get_device_info::*;
pub use self::get_logs::*;
pub use self::get_object_info::*;
pub use self::get_pubkey::*;
pub use self::list_objects::*;
pub use self::sign_ecdsa::*;
pub use self::sign_eddsa::*;

/// Structured commands (i.e. requests) which are encrypted and then sent to
/// the HSM. Every command has a corresponding `ResponseType`.
///
/// See <https://developers.yubico.com/YubiHSM2/Commands>
pub(crate) trait Command: Serialize + DeserializeOwned + Sized {
    /// Response type for this command
    type ResponseType: Response;

    /// Command ID for this command
    const COMMAND_TYPE: CommandType = Self::ResponseType::COMMAND_TYPE;
}

impl<C: Command> From<C> for CommandMessage {
    fn from(command: C) -> CommandMessage {
        Self::new(C::COMMAND_TYPE, serialize(&command).unwrap()).unwrap()
    }
}

/// Structured responses to `Command` messages sent from the HSM
pub(crate) trait Response: Serialize + DeserializeOwned + Sized {
    /// Command ID this response is for
    const COMMAND_TYPE: CommandType;

    /// Serialize a response type into a ResponseMessage
    #[cfg(feature = "mockhsm")]
    fn serialize(&self) -> ResponseMessage {
        ResponseMessage::success(Self::COMMAND_TYPE, serialize(self).unwrap())
    }
}
