use libusb;
use std::sync::Mutex;

use super::{Device, Devices, UsbConfig, UsbTimeout};
use super::{YUBIHSM2_BULK_IN_ENDPOINT, YUBIHSM2_BULK_OUT_ENDPOINT};
use command::MAX_MSG_SIZE;
use connector::{Connection, ConnectionError, ConnectionErrorKind::UsbError};
use uuid::Uuid;

/// Connection to HSM via USB
pub struct UsbConnection {
    /// Handle to the underlying USB device
    handle: Mutex<libusb::DeviceHandle<'static>>,

    /// YubiHSM2 USB device this connection is connected to
    device: Device,

    /// Timeout for reading from / writing to the YubiHSM2
    timeout: UsbTimeout,
}

impl UsbConnection {
    /// Connect to a YubiHSM2 using the given configuration
    pub fn open(config: &UsbConfig) -> Result<Self, ConnectionError> {
        Devices::open(config.serial, UsbTimeout::from_millis(config.timeout_ms))
    }

    /// Create a new YubiHSM device from a libusb device
    pub(super) fn new(device: Device, timeout: UsbTimeout) -> Result<Self, ConnectionError> {
        let handle = device.open_handle()?;

        let connection = UsbConnection {
            device,
            timeout,
            handle: Mutex::new(handle),
        };

        Ok(connection)
    }

    /// Borrow the `Device` for this connection
    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl Connection for UsbConnection {
    /// Send a command to the YubiHSM and read its response
    fn send_message(&self, _uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        let mut handle = self.handle.lock().unwrap();
        send_message(&mut handle, cmd.as_ref(), self.timeout)?;
        recv_message(&mut handle, self.timeout)
    }
}

impl Default for UsbConnection {
    fn default() -> Self {
        Devices::open(None, UsbTimeout::default()).unwrap()
    }
}

/// Write a bulk message to the YubiHSM 2
fn send_message(
    handle: &mut libusb::DeviceHandle,
    data: &[u8],
    timeout: UsbTimeout,
) -> Result<usize, ConnectionError> {
    let nbytes = handle.write_bulk(YUBIHSM2_BULK_OUT_ENDPOINT, data, timeout.duration())?;

    if data.len() == nbytes {
        Ok(nbytes)
    } else {
        fail!(
            UsbError,
            "incomplete bulk transfer: {} of {} bytes",
            nbytes,
            data.len()
        );
    }
}

/// Receive a message
fn recv_message(
    handle: &mut libusb::DeviceHandle,
    timeout: UsbTimeout,
) -> Result<Vec<u8>, ConnectionError> {
    // Allocate a buffer which is the maximum size we expect to receive
    let mut response = vec![0u8; MAX_MSG_SIZE];
    let nbytes = handle.read_bulk(YUBIHSM2_BULK_IN_ENDPOINT, &mut response, timeout.duration())?;

    response.truncate(nbytes);
    Ok(response)
}
