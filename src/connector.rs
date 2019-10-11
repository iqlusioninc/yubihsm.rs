//! Methods of connecting to a YubiHSM 2:
//!
//! - [HTTP][http-connector]: communicate with YubiHSM via the `yubihsm-connector`
//!   process from the Yubico SDK.
//! - [USB][usb-connector]: communicate directly with the YubiHSM over USB using
//!   the [rusb] crate.
//!
//! Additionally, this crate includes an optional development-only [mockhsm]
//! (gated under a `mockhsm` cargo feature) which can be used as a drop-in
//! replacement in places where you would like a simulated HSM for testing (e.g. CI).
//!
//! [http-connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html#method.http
//! [usb-connector]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html#method.usb
//! [rusb]: https://github.com/a1ien/rusb
//! [mockhsm]: https://docs.rs/yubihsm/latest/yubihsm/connector/struct.Connector.html#method.mockhsm

#[macro_use]
mod error;

mod connectable;
mod connection;
#[cfg(feature = "http")]
pub mod http;
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
    driver: Box<dyn Connectable>,
}

impl Connector {
    /// Create a new HTTP connector
    #[cfg(feature = "http")]
    pub fn http(config: &HttpConfig) -> Self {
        Self::from(HttpConnector::create(config))
    }

    /// Create a new USB connector. For more advanced usage including
    /// connecting to multiple YubiHSMs over USB which are plugged into
    /// the same computer, please see the [yubihsm::connector::usb] module.
    ///
    /// [yubihsm::connector::usb]: https://docs.rs/yubihsm/latest/yubihsm/connector/usb/index.html
    #[cfg(feature = "usb")]
    pub fn usb(config: &UsbConfig) -> Self {
        Self::from(UsbConnector::create(config))
    }

    /// Send a command message to the HSM, then read and return the response
    pub fn send_message(&self, uuid: Uuid, msg: Message) -> Result<Message, Error> {
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
