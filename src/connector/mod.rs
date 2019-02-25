//! Methods of connecting to a YubiHSM 2:
//!
//! - [HttpConnector]: communicates with HSM via the `yubihsm-connector` service's HTTP API
//! - [UsbConnector]: communicates with the HSM directly via USB using `libusb`.
//!
//! Additionally, [MockHsm] implements the `Connector` API and can be used as a drop-in replacement
//! in places where you would like a simulated HSM for testing (e.g. CI).
//!
//! [HttpConnector]: https://docs.rs/yubihsm/latest/yubihsm/connector/http/struct.HttpConnector.html
//! [UsbConnector]: https://docs.rs/yubihsm/latest/yubihsm/connector/usb/struct.UsbConnector.html
//! [MockHsm]: https://docs.rs/yubihsm/latest/yubihsm/mockhsm/struct.MockHsm.html

#[macro_use]
mod error;

mod connectable;
mod connection;
#[cfg(feature = "http")]
mod http;
mod message;
#[cfg(feature = "usb")]
pub mod usb;

pub use self::connection::Connection;
pub use self::error::*;
pub(crate) use self::{connectable::Connectable, message::Message};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[cfg(feature = "http")]
pub use self::http::HttpConfig;
#[cfg(feature = "http")]
use self::http::HttpConnector;

#[cfg(feature = "usb")]
pub use self::usb::UsbConfig;
#[cfg(feature = "usb")]
use self::usb::UsbConnector;

#[cfg(feature = "mockhsm")]
use crate::mockhsm::MockHsm;

/// Abstract interface to multiple types of YubiHSM 2 connections
pub struct Connector {
    /// Currently active connection (if any)
    connection: Arc<Mutex<Option<Box<dyn Connection>>>>,

    /// Backend connector driver
    driver: Box<Connectable>,
}

impl Connector {
    /// Create a new HTTP connector
    #[cfg(feature = "http")]
    pub fn http(config: &HttpConfig) -> Self {
        Self::from(HttpConnector::create(config))
    }

    /// Create a new USB connector
    #[cfg(feature = "usb")]
    pub fn usb(config: &UsbConfig) -> Self {
        Self::from(UsbConnector::create(config))
    }

    /// Send a command message to the HSM, then read and return the response
    pub fn send_message(&self, uuid: Uuid, msg: Message) -> Result<Message, ConnectionError> {
        let mut connection = self.connection.lock().unwrap();

        if connection.is_none() {
            *connection = Some(self.driver.connect()?);
        }

        connection
            .as_ref()
            .unwrap()
            .send_message(uuid, msg)
            .map_err(|e| {
                // In the event of an error, mark this connection as invalid
                *connection = None;
                e
            })
    }

    /// Create a mock HSM connector (useful for testing)
    #[cfg(feature = "mockhsm")]
    pub fn mockhsm() -> Self {
        let mockhsm: Box<dyn Connectable> = MockHsm::new().into();
        Self::from(mockhsm)
    }
}

impl Clone for Connector {
    fn clone(&self) -> Self {
        Connector {
            connection: self.connection.clone(),
            driver: self.driver.box_clone(),
        }
    }
}

impl From<Box<dyn Connectable>> for Connector {
    fn from(driver: Box<dyn Connectable>) -> Connector {
        Connector {
            connection: Arc::new(Mutex::new(None)),
            driver,
        }
    }
}
