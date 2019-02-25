//! Support for connecting to the YubiHSM 2 via USB

#[macro_use]
mod macros;

mod config;
mod connection;
mod device;
mod timeout;

pub use self::{
    config::UsbConfig,
    connection::UsbConnection,
    device::{Device, Devices},
    timeout::UsbTimeout,
};
use crate::connector::{Connectable, Connection, ConnectionError};

/// USB vendor ID for Yubico
pub const YUBICO_VENDOR_ID: u16 = 0x1050;

/// USB product ID for the YubiHSM 2
pub const YUBIHSM2_PRODUCT_ID: u16 = 0x0030;

/// YubiHSM 2 USB interface number
pub const YUBIHSM2_INTERFACE_NUM: u8 = 0;

/// YubiHSM 2 bulk out endpoint
pub const YUBIHSM2_BULK_OUT_ENDPOINT: u8 = 1;

/// YubiHSM 2 bulk in endpoint
pub const YUBIHSM2_BULK_IN_ENDPOINT: u8 = 0x81;

/// Connect to the HSM via USB.
///
/// `UsbConnector` is available when the `usb` cargo feature is enabled.
/// It requires `libusb` as a dependency, but does not otherwise need the
/// [Yubico SDK] (which is a vicarious dependency of `UsbConnector` which
/// needs the `yubihsm-connector` process).
///
/// [Yubico SDK]: https://developers.yubico.com/YubiHSM2/Releases/
#[derive(Clone, Default, Debug)]
pub struct UsbConnector(UsbConfig);

impl UsbConnector {
    /// Create a new `UsbConnector` with the given configuration
    pub fn create(config: &UsbConfig) -> Box<dyn Connectable> {
        Box::new(UsbConnector(config.clone()))
    }
}

impl Connectable for UsbConnector {
    /// Make a clone of this connectable as boxed trait object
    fn box_clone(&self) -> Box<dyn Connectable> {
        Box::new(UsbConnector(self.0.clone()))
    }

    /// Open a connection to `yubihsm-connector`
    fn connect(&self) -> Result<Box<dyn Connection>, ConnectionError> {
        Ok(Box::new(UsbConnection::open(&self.0)?))
    }
}

impl Into<Box<Connectable>> for UsbConnector {
    fn into(self) -> Box<Connectable> {
        Box::new(self)
    }
}
