//! HSM device-related functionality

pub(crate) mod commands;
mod error;
mod serial_number;

pub use self::{
    error::{DeviceError, DeviceErrorKind},
    serial_number::SerialNumber,
};
