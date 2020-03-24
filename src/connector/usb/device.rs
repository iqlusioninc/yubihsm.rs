//! Support for connecting to the YubiHSM 2 USB device using rusb

use super::{
    UsbConnection, UsbTimeout, YUBICO_VENDOR_ID, YUBIHSM2_BULK_IN_ENDPOINT, YUBIHSM2_INTERFACE_NUM,
    YUBIHSM2_PRODUCT_ID,
};
use crate::{
    command::MAX_MSG_SIZE,
    connector::{
        self,
        ErrorKind::{AddrInvalid, DeviceBusyError, UsbError},
    },
    device::SerialNumber,
};
use anomaly::{fail, format_err};
use std::{
    fmt::{self, Debug},
    slice::Iter,
    time::Duration,
    vec::IntoIter,
};

/// A collection of detected YubiHSM 2 devices, represented as `Device`
pub struct Devices(Vec<Device>);

impl Devices {
    /// Return the serial numbers of all connected YubiHSM 2s
    pub fn serial_numbers() -> Result<Vec<SerialNumber>, connector::Error> {
        let devices = Self::detect(UsbTimeout::default())?;
        let serials: Vec<_> = devices.iter().map(|a| a.serial_number).collect();
        Ok(serials)
    }

    /// Open a YubiHSM 2, either selecting one with a particular serial number
    /// or opening the only available one if `None`there is only one connected
    pub fn open(
        serial_number: Option<SerialNumber>,
        timeout: UsbTimeout,
    ) -> Result<UsbConnection, connector::Error> {
        let mut devices = Self::detect(timeout)?;

        if let Some(sn) = serial_number {
            while let Some(device) = devices.0.pop() {
                if device.serial_number == sn {
                    return device.open(timeout);
                }
            }

            fail!(
                UsbError,
                "no YubiHSM 2 found with serial number: {:?}",
                serial_number
            )
        } else {
            match devices.0.len() {
                1 => devices.0.remove(0).open(timeout),
                0 => fail!(UsbError, "no YubiHSM 2 devices detected"),
                _ => fail!(
                    UsbError,
                    "expected a single YubiHSM 2 device to be connected, found {}: {}",
                    devices.0.len(),
                    devices
                        .0
                        .iter()
                        .map(|d| d.serial_number.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
    }

    /// Detect connected YubiHSM 2s, returning a collection of them
    pub fn detect(timeout: UsbTimeout) -> Result<Self, connector::Error> {
        use rusb::UsbContext;
        let device_list = rusb::Context::new()?.devices()?;
        let mut devices = vec![];

        debug!("USB: enumerating devices...");

        for device in device_list.iter() {
            let desc = device.device_descriptor()?;

            if desc.vendor_id() != YUBICO_VENDOR_ID || desc.product_id() != YUBIHSM2_PRODUCT_ID {
                continue;
            }

            usb_debug!(device, "found YubiHSM device");

            let mut handle = device
                .open()
                .map_err(|e| usb_err!(device, "error opening device: {}", e))?;

            handle.reset().map_err(|error| match error {
                rusb::Error::NoDevice => format_err!(
                    DeviceBusyError,
                    "USB(bus={},addr={}): couldn't reset device (already in use or disconnected)",
                    device.bus_number(),
                    device.address()
                ),
                other => usb_err!(device, "error resetting device: {}", other),
            })?;

            let language = *handle
                .read_languages(timeout.duration())?
                .first()
                .ok_or_else(|| {
                    usb_err!(
                        device,
                        "couldn't read YubiHSM serial number (missing language info)"
                    )
                })?;

            let t = timeout.duration();
            let manufacturer = handle.read_manufacturer_string(language, &desc, t)?;
            let product = handle.read_product_string(language, &desc, t)?;
            let product_name = format!("{} {}", manufacturer, product);
            let serial_number: SerialNumber = handle
                .read_serial_number_string(language, &desc, t)?
                .parse()
                .map_err(|e| format_err!(AddrInvalid, "{}", e))?;

            debug!(
                "USB(bus={},addr={}): found {} (serial #{})",
                device.bus_number(),
                device.address(),
                product_name,
                serial_number,
            );

            devices.push(Device::new(device, product_name, serial_number));
        }

        if devices.is_empty() {
            debug!("no YubiHSM 2 devices found");
        }

        Ok(Devices(devices))
    }

    /// Number of detected devices
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Did we fail to find any YubiHSM 2 devices?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the detected devices as a slice
    pub fn as_slice(&self) -> &[Device] {
        self.0.as_slice()
    }

    /// Iterate over the detected YubiHSM 2s
    pub fn iter(&self) -> Iter<'_, Device> {
        self.0.iter()
    }
}

impl IntoIterator for Devices {
    type Item = Device;
    type IntoIter = IntoIter<Device>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// A USB device we've identified as a YubiHSM 2
pub struct Device {
    /// Underlying `rusb` device
    pub(super) device: rusb::Device<rusb::Context>,

    /// Product vendor and name
    pub product_name: String,

    /// Serial number of the YubiHSM 2 device
    pub serial_number: SerialNumber,
}

impl Device {
    /// Create a new device
    pub(super) fn new(
        device: rusb::Device<rusb::Context>,
        product_name: String,
        serial_number: SerialNumber,
    ) -> Self {
        Self {
            serial_number,
            product_name,
            device,
        }
    }

    /// Open this device, consuming it and creating a `UsbConnection`
    pub fn open(self, timeout: UsbTimeout) -> Result<UsbConnection, connector::Error> {
        let connection = UsbConnection::create(self, timeout)?;

        debug!(
            "USB(bus={},addr={}): successfully opened {} (serial #{})",
            connection.device().bus_number(),
            connection.device().address(),
            connection.device().product_name,
            connection.device().serial_number,
        );

        Ok(connection)
    }

    /// Get the bus number for this device
    pub fn bus_number(&self) -> u8 {
        self.device.bus_number()
    }

    /// Get the address for this device
    pub fn address(&self) -> u8 {
        self.device.address()
    }

    /// Open a handle to the underlying device (for use by `UsbConnection`)
    pub(super) fn open_handle(
        &self,
    ) -> Result<rusb::DeviceHandle<rusb::Context>, connector::Error> {
        let mut handle = self.device.open()?;
        handle.reset()?;
        handle.claim_interface(YUBIHSM2_INTERFACE_NUM)?;

        // Flush any unconsumed messages still in the buffer
        flush(&mut handle)?;

        Ok(handle)
    }
}

impl Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "yubihsm::connector::usb::Device(bus={} addr={} serial=#{})",
            self.bus_number(),
            self.address(),
            self.serial_number,
        )
    }
}

/// Flush any unconsumed messages still in the buffer to get the connection
/// back into a clean state
fn flush(handle: &mut rusb::DeviceHandle<rusb::Context>) -> Result<(), connector::Error> {
    let mut buffer = [0u8; MAX_MSG_SIZE];

    // Use a near instantaneous (but non-zero) timeout to drain the buffer.
    // Zero is interpreted as wait forever.
    let timeout = Duration::from_millis(1);

    match handle.read_bulk(YUBIHSM2_BULK_IN_ENDPOINT, &mut buffer, timeout) {
        Ok(_) | Err(rusb::Error::Timeout) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
