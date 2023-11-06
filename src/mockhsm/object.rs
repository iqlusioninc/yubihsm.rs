//! Objects stored inside of the `MockHsm`

#![allow(unknown_lints, renamed_and_removed_lints, too_many_arguments)]

mod objects;
mod payload;

pub(crate) use self::{objects::Objects, payload::Payload};
use crate::{object, wrap, Algorithm};
use serde::{Deserialize, Serialize};

/// Label for the default auth key
const DEFAULT_AUTHENTICATION_KEY_LABEL: &str = "DEFAULT AUTHKEY CHANGE THIS ASAP";

/// An individual object in the `MockHsm`, specialized for a given object type
#[derive(Debug)]
pub(crate) struct Object {
    pub object_info: object::Info,
    pub payload: Payload,
}

impl Object {
    /// Get the algorithm of the payload
    pub fn algorithm(&self) -> Algorithm {
        self.payload.algorithm()
    }

    /// Get the `object::Info`
    pub fn info(&self) -> &object::Info {
        &self.object_info
    }
}

/// A serialized object which can be exported/imported
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct WrappedObject {
    pub alg_id: Algorithm,
    pub object_info: wrap::Info,
    pub data: Vec<u8>,
}

impl<'a> From<&'a Object> for WrappedObject {
    fn from(obj: &'a Object) -> Self {
        Self {
            alg_id: Algorithm::Wrap(wrap::Algorithm::Aes128Ccm),
            object_info: obj.object_info.clone().into(),
            data: obj.payload.to_bytes(),
        }
    }
}

impl<'a> From<&'a Object> for object::Entry {
    fn from(obj: &'a Object) -> Self {
        object::Entry {
            object_id: obj.object_info.object_id,
            object_type: obj.object_info.object_type,
            sequence: obj.object_info.sequence,
        }
    }
}
