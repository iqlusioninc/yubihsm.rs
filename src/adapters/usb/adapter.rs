use libusb;
use std::sync::Mutex;

use super::{
    HsmDevice, UsbConfig, UsbDevices, UsbTimeout, YUBIHSM2_BULK_IN_ENDPOINT,
    YUBIHSM2_BULK_OUT_ENDPOINT,
};
use adapters::{Adapter, AdapterError, AdapterErrorKind::UsbError};
use securechannel::MAX_MSG_SIZE;
use serial_number::SerialNumber;
use uuid::Uuid;

/// `libusb`-based adapter which communicates directly with the YubiHSM2
pub struct UsbAdapter {
    /// Handle to the underlying USB device
    handle: Mutex<libusb::DeviceHandle<'static>>,

    /// YubiHSM2 USB device this adapter is connected to
    pub device: HsmDevice,

    /// Timeout for reading from / writing to the YubiHSM2
    pub timeout: UsbTimeout,
}

impl UsbAdapter {
    /// Create a new YubiHSM device from a libusb device
    pub(super) fn new(device: HsmDevice, timeout: UsbTimeout) -> Result<Self, AdapterError> {
        let handle = device.open_handle()?;

        let adapter = UsbAdapter {
            device,
            timeout,
            handle: Mutex::new(handle),
        };

        Ok(adapter)
    }
}

impl Adapter for UsbAdapter {
    type Config = UsbConfig;

    /// Connect to a YubiHSM2 using the given configuration
    fn open(config: &UsbConfig) -> Result<Self, AdapterError> {
        UsbDevices::open(config.serial, UsbTimeout::from_millis(config.timeout_ms))
    }

    /// Check that we still have an active USB connection
    fn healthcheck(&self) -> Result<(), AdapterError> {
        let handle = self.handle.lock().unwrap();

        // TODO: better test that our USB connection is still open?
        if let Err(e) = handle.active_configuration() {
            fail!(UsbError, "healthcheck failed: {}", e);
        }

        Ok(())
    }

    /// Get the serial number for the current YubiHSM2 (if available)
    fn serial_number(&self) -> Result<SerialNumber, AdapterError> {
        Ok(self.device.serial_number)
    }

    /// Send a command to the YubiHSM and read its response
    fn send_message(&self, _uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let mut handle = self.handle.lock().unwrap();
        send_message(&mut handle, cmd.as_ref(), self.timeout)?;
        recv_message(&mut handle, self.timeout)
    }
}

impl Default for UsbAdapter {
    fn default() -> Self {
        UsbDevices::open(None, UsbTimeout::default()).unwrap()
    }
}

/// Write a bulk message to the YubiHSM 2
fn send_message(
    handle: &mut libusb::DeviceHandle,
    data: &[u8],
    timeout: UsbTimeout,
) -> Result<usize, AdapterError> {
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
) -> Result<Vec<u8>, AdapterError> {
    // Allocate a buffer which is the maximum size we expect to receive
    let mut response = vec![0u8; MAX_MSG_SIZE];
    let nbytes = handle.read_bulk(YUBIHSM2_BULK_IN_ENDPOINT, &mut response, timeout.duration())?;

    response.truncate(nbytes);
    Ok(response)
}
