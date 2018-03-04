//! Responses to commands sent from the HSM, intended as part of the public
//! API of this crate.

pub use failure::Error;
pub(crate) use securechannel::CommandType;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;

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

pub(crate) trait Response: Serialize + DeserializeOwned + Sized {
    /// Command ID this response is for
    const COMMAND_TYPE: CommandType;
}
