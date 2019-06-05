//! Trait for YubiHSM2 interfaces which can be connected to

use crate::connector::{self, Connection};

/// Connectors which create `Connection` objects to the HSM
pub trait Connectable: Send + Sync {
    /// Make a clone of this connectable as boxed trait object
    fn box_clone(&self) -> Box<dyn Connectable>;

    /// Open a connection to the HSM using this `Connector`
    fn connect(&self) -> Result<Box<dyn Connection>, connector::Error>;
}
