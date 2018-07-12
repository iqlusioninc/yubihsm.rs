//! Objects within the `YubiHSM2` (keys, certificates, or other opaque data)

mod handle;
mod info;
mod label;
mod origins;
mod types;

pub(crate) use self::handle::Handle as ObjectHandle;
pub use self::info::Info as ObjectInfo;
pub use self::label::Label as ObjectLabel;
pub use self::origins::Origin as ObjectOrigin;
pub use self::types::Type as ObjectType;

/// Object identifiers
pub type ObjectId = u16;

/// Sequence identifiers: number of times an object with a given ID has been
/// created in this `YubiHSM` (with all previous versions having been deleted)
pub type SequenceId = u8;
