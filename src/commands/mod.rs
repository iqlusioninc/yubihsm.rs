//! Command (i.e. request) and response structs for `YubiHSM2` commands
//!
//! The eventual goal is to procedurally generate serializers/deserializers
//! for all of these structs declaratively (using e.g. serde). See:
//!
//! <https://github.com/tendermint/yubihsm-client/issues/3>

mod delete_object;
mod echo;
mod gen_asymmetric_key;
mod get_object_info;
mod list_objects;

pub use self::delete_object::DeleteObjectCommand;
pub use self::echo::EchoCommand;
pub use self::gen_asymmetric_key::GenAsymmetricKeyCommand;
pub use self::get_object_info::GetObjectInfoCommand;
pub use self::list_objects::ListObjectsCommand;

#[cfg(feature = "mockhsm")]
pub use failure::Error;
use responses::Response;
use securechannel::{CommandMessage, CommandType};

pub(crate) trait Command: Into<CommandMessage> {
    /// Command ID for this command
    const COMMAND_TYPE: CommandType;

    /// Response type for this command
    type ResponseType: Response;

    /// Serialize this command as a byte vector
    fn into_vec(self) -> Vec<u8>;

    /// Deserialize command from an encrypted channel message
    #[cfg(feature = "mockhsm")]
    fn parse(command_msg: CommandMessage) -> Result<Self, Error>;
}

impl<C: Command> From<C> for CommandMessage {
    fn from(command: C) -> CommandMessage {
        Self::new(C::COMMAND_TYPE, command.into_vec())
    }
}
