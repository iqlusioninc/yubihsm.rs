use libusb;
use std::sync::Mutex;

use super::{
    HsmDevice, UsbConfig, UsbDevices, UsbTimeout, YUBIHSM2_BULK_IN_ENDPOINT,
    YUBIHSM2_BULK_OUT_ENDPOINT,
};
use connection::{Connection, ConnectionError, ConnectionErrorKind::UsbError};
use serial_number::SerialNumber;
use session::MAX_MSG_SIZE;
use uuid::Uuid;

/// Connection to HSM via USB
pub struct UsbConnection {
    /// Handle to the underlying USB device
    handle: Mutex<libusb::DeviceHandle<'static>>,

    /// YubiHSM2 USB device this connection is connected to
    device: HsmDevice,

    /// Timeout for reading from / writing to the YubiHSM2
    timeout: UsbTimeout,
}

impl UsbConnection {
    /// Create a new YubiHSM device from a libusb device
    pub(super) fn new(device: HsmDevice, timeout: UsbTimeout) -> Result<Self, ConnectionError> {
        let handle = device.open_handle()?;

        let connection = UsbConnection {
            device,
            timeout,
            handle: Mutex::new(handle),
        };

        Ok(connection)
    }

    /// Borrow the `HsmDevice` for this connection
    pub fn device(&self) -> &HsmDevice {
        &self.device
    }
}

impl Connection for UsbConnection {
    type Config = UsbConfig;

    /// Connect to a YubiHSM2 using the given configuration
    fn open(config: &UsbConfig) -> Result<Self, ConnectionError> {
        UsbDevices::open(config.serial, UsbTimeout::from_millis(config.timeout_ms))
    }

    /// Check that we still have an active USB connection
    fn healthcheck(&self) -> Result<(), ConnectionError> {
        let handle = self.handle.lock().unwrap();

        // TODO: better test that our USB connection is still open?
        if let Err(e) = handle.active_configuration() {
            fail!(UsbError, "healthcheck failed: {}", e);
        }

        Ok(())
    }

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, ConnectionError> {
        Ok(self.device.serial_number)
    }

    /// Send a command to the YubiHSM and read its response
    fn send_message(&self, _uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        let mut handle = self.handle.lock().unwrap();
        send_message(&mut handle, cmd.as_ref(), self.timeout)?;
        recv_message(&mut handle, self.timeout)
    }
}

impl Default for UsbConnection {
    fn default() -> Self {
        UsbDevices::open(None, UsbTimeout::default()).unwrap()
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
