use libusb;
use std::{
    fmt::{self, Debug},
    sync::Mutex,
    time::Duration,
};

use super::{UsbConfig, UsbDevices, UsbTimeout};
use adapters::{Adapter, AdapterError, AdapterErrorKind::UsbError};
use securechannel::MAX_MSG_SIZE;
use serial_number::SerialNumber;
use uuid::Uuid;

/// YubiHSM 2 USB interface number
const YUBIHSM2_INTERFACE_NUM: u8 = 0;

/// YubiHSM 2 bulk out endpoint
const YUBIHSM2_BULK_OUT_ENDPOINT: u8 = 1;

/// YubiHSM 2 bulk in endpoint
const YUBIHSM2_BULK_IN_ENDPOINT: u8 = 0x81;

/// `libusb`-based adapter which communicates directly with the YubiHSM2
pub struct UsbAdapter {
    /// Handle to the underlying USB device
    handle: Mutex<libusb::DeviceHandle<'static>>,

    /// USB bus number for this device
    pub bus_number: u8,

    /// USB device address for this device
    pub device_address: u8,

    /// Serial number of the device
    pub serial_number: SerialNumber,

    /// Timeout for reading from / writing to the YubiHSM2
    pub timeout: UsbTimeout,
}

impl UsbAdapter {
    /// Create a new YubiHSM device from a libusb device
    pub(super) fn new(
        device: &libusb::Device<'static>,
        serial_number: SerialNumber,
        timeout: UsbTimeout,
    ) -> Result<Self, AdapterError> {
        let mut handle = device.open()?;
        handle.reset()?;
        handle.claim_interface(YUBIHSM2_INTERFACE_NUM)?;

        // Flush any unconsumed messages still in the buffer
        flush(&mut handle)?;

        let adapter = UsbAdapter {
            bus_number: device.bus_number(),
            device_address: device.address(),
            serial_number,
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
        Ok(self.serial_number)
    }

    /// Send a command to the YubiHSM and read its response
    fn send_message(&self, _uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let mut handle = self.handle.lock().unwrap();
        send_message(&mut handle, cmd.as_ref(), self.timeout)?;
        recv_message(&mut handle, self.timeout)
    }
}

impl Debug for UsbAdapter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "yubihsm::UsbAdapter(bus={} addr={} serial=#{:?} timeout={:?})",
            self.bus_number,
            self.device_address,
            self.serial_number.as_str(),
            self.timeout.duration()
        )
    }
}

impl Default for UsbAdapter {
    fn default() -> Self {
        UsbDevices::open(None, UsbTimeout::default()).unwrap()
    }
}

/// Flush any unconsumed messages still in the buffer to get the connection
/// back into a clean state
fn flush(handle: &mut libusb::DeviceHandle) -> Result<(), AdapterError> {
    let mut buffer = [0u8; MAX_MSG_SIZE];

    // Use a near instantaneous (but non-zero) timeout to drain the buffer.
    // Zero is interpreted as wait forever.
    let timeout = Duration::from_millis(1);

    match handle.read_bulk(YUBIHSM2_BULK_IN_ENDPOINT, &mut buffer, timeout) {
        Ok(_) | Err(libusb::Error::Timeout) => Ok(()),
        Err(e) => Err(e.into()),
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
