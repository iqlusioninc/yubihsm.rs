//! Objects stored inside of the `MockHsm`

#![allow(unknown_lints, renamed_and_removed_lints, too_many_arguments)]

mod objects;
mod payload;

pub(crate) use self::objects::Objects;
pub(crate) use self::payload::Payload;
use {Algorithm, ObjectInfo};

/// Size of the wrap algorithm's MAC tag. The MockHsm uses AES-GCM instead of
/// AES-CCM as there isn't a readily available Rust implementation
const WRAPPED_DATA_MAC_SIZE: usize = 16;

/// Label for the default auth key
const DEFAULT_AUTH_KEY_LABEL: &str = "DEFAULT AUTHKEY CHANGE THIS ASAP";

/// An individual object in the `MockHsm`, specialized for a given object type
#[derive(Debug)]
pub(crate) struct Object {
    pub object_info: ObjectInfo,
    pub payload: Payload,
}

impl Object {
    /// Get the algorithm of the payload
    pub fn algorithm(&self) -> Algorithm {
        self.payload.algorithm()
    }

    /// Get the `ObjectInfo`
    pub fn info(&self) -> &ObjectInfo {
        &self.object_info
    }
}

/// A serialized object which can be exported/imported
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrappedObject {
    pub object_info: ObjectInfo,
    pub data: Vec<u8>,
}

impl<'a> From<&'a Object> for WrappedObject {
    fn from(obj: &'a Object) -> Self {
        Self {
            object_info: obj.object_info.clone(),
            data: obj.payload.as_ref().into(),
        }
    }
}
