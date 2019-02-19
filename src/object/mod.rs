//! Objects within the `YubiHSM2` (keys, certificates, or other opaque data)

mod handle;
mod info;
mod label;
mod origins;
mod params;
mod types;

pub(crate) use self::handle::Handle;
pub use self::{
    info::Info,
    label::{Label, LABEL_SIZE},
    origins::Origin,
    params::ImportParams,
    types::Type,
};

/// Object identifiers
pub type Id = u16;

/// Sequence identifiers: number of times an object with a given ID has been
/// created in this `YubiHSM` (with all previous versions having been deleted)
pub type SequenceId = u8;
