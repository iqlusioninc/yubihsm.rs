use libusb;
use std::{process::exit, slice::Iter, str::FromStr};

use super::{HsmDevice, UsbAdapter, UsbTimeout, YUBICO_VENDOR_ID, YUBIHSM2_PRODUCT_ID};
use adapter::{
    AdapterError,
    AdapterErrorKind::{DeviceBusyError, UsbError},
};
use serial_number::SerialNumber;

lazy_static! {
    /// Global USB context for accessing YubiHSM2s
    static ref GLOBAL_USB_CONTEXT: libusb::Context = libusb::Context::new().unwrap_or_else(|e| {
        eprintln!("*** ERROR: yubihsm-rs USB context init failed: {}", e);
        exit(1);
    });
}

/// A collection of detected YubiHSM 2 devices, represented as `HsmDevice`
pub struct UsbDevices(Vec<HsmDevice>);

impl UsbDevices {
    /// Return the serial numbers of all connected YubiHSM2s
    pub fn serials() -> Result<Vec<SerialNumber>, AdapterError> {
        let devices = Self::new(UsbTimeout::default())?;
        let serials: Vec<_> = devices.iter().map(|a| a.serial_number).collect();
        Ok(serials)
    }

    /// Open a YubiHSM2, either selecting one with a particular serial number
    /// or opening the only available one if `None`there is only one connected
    pub fn open(
        serial_number: Option<SerialNumber>,
        timeout: UsbTimeout,
    ) -> Result<UsbAdapter, AdapterError> {
        let mut devices = Self::new(timeout)?;

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
        } else if devices.0.len() == 1 {
            devices.0.remove(0).open(timeout)
        } else {
            fail!(
                UsbError,
                "expected a single YubiHSM device to be connected, found {}: {:?}",
                devices.0.len(),
                devices
                    .0
                    .iter()
                    .map(|d| d.serial_number.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    /// Detect connected YubiHSM 2s, returning a collection of them
    pub fn new(timeout: UsbTimeout) -> Result<Self, AdapterError> {
        let device_list = GLOBAL_USB_CONTEXT.devices()?;
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
                libusb::Error::NoDevice => err!(
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
            let serial_number = handle.read_serial_number_string(language, &desc, t)?;
            let product_name = format!("{} {}", manufacturer, product);

            debug!(
                "USB(bus={},addr={}): found {} (serial #{})",
                device.bus_number(),
                device.address(),
                &product_name,
                serial_number.as_str(),
            );

            devices.push(HsmDevice::new(
                device,
                product_name,
                SerialNumber::from_str(&serial_number)?,
            ));
        }

        if devices.is_empty() {
            debug!("no YubiHSM 2 devices found");
        }

        Ok(UsbDevices(devices))
    }

    /// Iterate over the detected YubiHSM 2s
    pub fn iter(&self) -> Iter<HsmDevice> {
        self.0.iter()
    }
}
