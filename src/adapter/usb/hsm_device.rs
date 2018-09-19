use libusb;
use std::{
    fmt::{self, Debug},
    time::Duration,
};

use super::{UsbAdapter, UsbTimeout, YUBIHSM2_BULK_IN_ENDPOINT, YUBIHSM2_INTERFACE_NUM};
use adapter::AdapterError;
use securechannel::MAX_MSG_SIZE;
use serial_number::SerialNumber;

/// A USB device we've identified as a YubiHSM2
pub struct HsmDevice {
    /// Underlying `libusb` device
    pub(super) device: libusb::Device<'static>,

    /// Product vendor and name
    pub product_name: String,

    /// Serial number of the YubiHSM2 device
    pub serial_number: SerialNumber,
}

impl HsmDevice {
    /// Create a new device
    pub(super) fn new(
        device: libusb::Device<'static>,
        product_name: String,
        serial_number: SerialNumber,
    ) -> Self {
        Self {
            serial_number,
            product_name,
            device,
        }
    }

    /// Open this device, consuming it and creating a `UsbAdapter`
    pub fn open(self, timeout: UsbTimeout) -> Result<UsbAdapter, AdapterError> {
        let adapter = UsbAdapter::new(self, timeout)?;

        info!(
            "USB(bus={},addr={}): successfully opened {} (serial #{})",
            adapter.device().bus_number(),
            adapter.device().address(),
            adapter.device().product_name.as_str(),
            adapter.device().serial_number.as_str(),
        );

        Ok(adapter)
    }

    /// Get the bus number for this device
    pub fn bus_number(&self) -> u8 {
        self.device.bus_number()
    }

    /// Get the address for this device
    pub fn address(&self) -> u8 {
        self.device.address()
    }

    /// Open a handle to the underlying device (for use by `UsbAdapter`)
    pub(super) fn open_handle(&self) -> Result<libusb::DeviceHandle<'static>, AdapterError> {
        let mut handle = self.device.open()?;
        handle.reset()?;
        handle.claim_interface(YUBIHSM2_INTERFACE_NUM)?;

        // Flush any unconsumed messages still in the buffer
        flush(&mut handle)?;

        Ok(handle)
    }
}

impl Debug for HsmDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "HsmDevice(bus={} addr={} serial=#{})",
            self.bus_number(),
            self.address(),
            self.serial_number,
        )
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
