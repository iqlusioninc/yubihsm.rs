//! Responses to commands sent from the HSM, intended as part of the public
//! API of this crate.

mod delete_object;
mod echo;
mod gen_asymmetric_key;
mod get_object_info;
mod list_objects;

pub use self::delete_object::DeleteObjectResponse;
pub use self::echo::EchoResponse;
pub use self::gen_asymmetric_key::GenAsymmetricKeyResponse;
pub use self::get_object_info::GetObjectInfoResponse;
pub use self::list_objects::{ListObjectsEntry, ListObjectsResponse};

pub use failure::Error;
pub(crate) use securechannel::CommandType;

pub(crate) trait Response: Sized {
    /// Command ID this response is for
    const COMMAND_TYPE: CommandType;

    /// Parse response data into a response object
    fn parse(bytes: Vec<u8>) -> Result<Self, Error>;

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8>;
}
