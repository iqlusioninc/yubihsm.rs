//! Secure Shell Certificate Authority Functionality
//!
//! **WARNING**: This functionality has not been tested and has not yet been
//! confirmed to actually work! USE AT YOUR OWN RISK!
//!
//! You will need to enable the `untested` cargo feature to use it.

mod certificate;
#[cfg(feature = "untested")]
pub(crate) mod commands;
mod template;

pub use self::{certificate::Certificate, template::Template};
