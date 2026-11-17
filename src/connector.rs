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
use crate::{
    command, device,
    device::commands::DeviceInfoResponse,
    response,
    serialization::deserialize,
    uuid::{self, Uuid},
};
use std::sync::{Arc, Mutex};

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

    /// Create a mock HSM connector (useful for testing)
    #[cfg(feature = "mockhsm")]
    pub fn mockhsm() -> Self {
        let mockhsm: Box<dyn Connectable> = MockHsm::new().into();
        Self::from(mockhsm)
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
            .inspect_err(|_| {
                // In the event of an error, mark this connection as invalid
                *connection = None;
            })
    }

    /// Get information about the HSM device *without* establishing a session.
    ///
    /// The response is **not authenticated**. A session response is R-MAC'd
    /// under the SCP03 session keys, so it is provably from the device and
    /// provably fresh; this one is not, so anything on the path between this
    /// process and the device can forge or replay it. Treat these values as a
    /// hint, never as evidence. Use [`Client::device_info`] when the answer has
    /// to be trustworthy.
    ///
    /// <https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#get-device-info-command>
    ///
    /// [`Client::device_info`]: crate::Client::device_info
    pub fn device_info(&self) -> Result<device::Info, Error> {
        let command = command::Message::create(command::Code::DeviceInfo, vec![])
            .map_err(|e| ErrorKind::RequestError.context(e))?;

        let response = response::Message::parse(self.send_message(uuid::new_v4(), command.into())?)
            .map_err(|e| ErrorKind::ResponseError.context(e))?;

        if response.is_err() {
            match device::ErrorKind::from_response_message(&response) {
                Some(kind) => fail!(ErrorKind::ResponseError, "HSM error: {}", kind),
                None => fail!(ErrorKind::ResponseError, "HSM error: {:?}", response.code),
            }
        }

        if response.command() != Some(command::Code::DeviceInfo) {
            fail!(
                ErrorKind::ResponseError,
                "unexpected response type: {:?}",
                response.code
            );
        }

        Ok(deserialize::<DeviceInfoResponse>(&response.data)
            .map_err(|e| ErrorKind::ResponseError.context(e))?
            .into())
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

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("driver", &self.driver)
            .finish()
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
