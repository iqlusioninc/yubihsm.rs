use libusb;
use std::{
    fmt::{self, Debug},
    sync::Mutex,
    time::Duration,
};

use super::{UsbDevices, UsbTimeout};
use adapters::{Adapter, AdapterError};
use securechannel::MAX_MSG_SIZE;
use serial::SerialNumber;
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
            serial_number,
            timeout,
            handle: Mutex::new(handle),
        };

        Ok(adapter)
    }
}

impl Adapter for UsbAdapter {
    type Config = UsbConfig;
    type Status = ();

    /// We don't bother to implement this
    fn open(_config: UsbConfig) -> Result<Self, AdapterError> {
        panic!("unimplemented");
    }

    /// If we get a reconnect signal, rescan USB devices looking for a YubiHSM2
    /// with the same serial number. If we find it, open a new handle and
    /// replace the old one.
    fn reconnect(&self) -> Result<(), AdapterError> {
        println!(
            "resetting YubiHSM 2 (serial #{})",
            self.serial_number.as_str()
        );

        let mut handle = self.handle.lock().unwrap();

        // Make a best effort to release the current interface
        let _ = handle.release_interface(YUBIHSM2_INTERFACE_NUM);

        // Rescan the device bus for a YubiHSM 2 with the same serial number, opening a
        // new adapter (whose handle we'll steal and claim as our own)
        let new_handle = UsbDevices::open(Some(self.serial_number), self.timeout)?.handle;

        // If we found one, replace the old one
        *handle = new_handle.into_inner().unwrap();

        println!(
            "successfully reset YubiHSM 2 (serial #{})",
            self.serial_number.as_str()
        );

        Ok(())
    }

    /// Stub (TODO: remove this from the trait)
    fn status(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    /// Send a command to the YubiHSM and read its response
    fn send_command(&self, _uuid: Uuid, cmd: Vec<u8>) -> Result<Vec<u8>, AdapterError> {
        let mut handle = self.handle.lock().unwrap();
        send_message(&mut handle, cmd.as_ref(), self.timeout)?;
        recv_message(&mut handle, self.timeout)
    }
}

impl Debug for UsbAdapter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "yubihsm::UsbAdapter {{ serial_number: {:?}, timeout: {:?} }}",
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

/// Fake config
// TODO: real config
#[derive(Debug, Default)]
pub struct UsbConfig;

impl fmt::Display for UsbConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(nothing to see here)")
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
        adapter_fail!(
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
