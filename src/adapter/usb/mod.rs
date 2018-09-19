//! Support for interacting directly with the YubiHSM 2 via USB

#[macro_use]
mod macros;

mod adapter;
mod config;
mod devices;
mod hsm_device;
mod timeout;

pub use self::adapter::UsbAdapter;
pub use self::config::UsbConfig;
pub use self::devices::UsbDevices;
pub use self::hsm_device::HsmDevice;
pub use self::timeout::UsbTimeout;

/// USB vendor ID for Yubico
pub const YUBICO_VENDOR_ID: u16 = 0x1050;

/// USB product ID for the YubiHSM2
pub const YUBIHSM2_PRODUCT_ID: u16 = 0x0030;

/// YubiHSM 2 USB interface number
pub const YUBIHSM2_INTERFACE_NUM: u8 = 0;

/// YubiHSM 2 bulk out endpoint
pub const YUBIHSM2_BULK_OUT_ENDPOINT: u8 = 1;

/// YubiHSM 2 bulk in endpoint
pub const YUBIHSM2_BULK_IN_ENDPOINT: u8 = 0x81;
