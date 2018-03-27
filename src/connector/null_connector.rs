//! Stubbed connector used if we build without reqwest

use super::{Connector, Error, Status};

/// Stubbed connector
pub struct NullConnector {}

impl Connector for NullConnector {
    fn open(_url: &str) -> Result<Self, Error> {
        panic!("unimplemented");
    }

    fn status(&self) -> Result<Status, Error> {
        panic!("unimplemented");
    }

    fn send_command(&self, _cmd: Vec<u8>) -> Result<Vec<u8>, Error> {
        panic!("unimplemented");
    }
}
