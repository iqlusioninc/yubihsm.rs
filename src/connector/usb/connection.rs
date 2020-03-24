//! Connections to the YubiHSM 2 via USB

use super::{
    Device, Devices, UsbConfig, UsbTimeout, YUBIHSM2_BULK_IN_ENDPOINT, YUBIHSM2_BULK_OUT_ENDPOINT,
};
use crate::{
    command::MAX_MSG_SIZE,
    connector::{self, Connection, ErrorKind::UsbError, Message},
};
use anomaly::fail;
use std::sync::Mutex;
use uuid::Uuid;

/// Number of times to retry a bulk message receive operation before giving up
const MAX_RECV_RETRIES: usize = 3;

/// Connection to HSM via USB
pub struct UsbConnection {
    /// Handle to the underlying USB device
    handle: Mutex<rusb::DeviceHandle<rusb::Context>>,

    /// YubiHSM 2 USB device this connection is connected to
    device: Device,

    /// Timeout for reading from / writing to the YubiHSM 2
    timeout: UsbTimeout,
}

impl UsbConnection {
    /// Connect to a YubiHSM 2 using the given configuration
    pub fn open(config: &UsbConfig) -> Result<Self, connector::Error> {
        Devices::open(config.serial, UsbTimeout::from_millis(config.timeout_ms))
    }

    /// Create a new YubiHSM device from a rusb device
    pub(super) fn create(device: Device, timeout: UsbTimeout) -> Result<Self, connector::Error> {
        let mut handle = device.open_handle()?;

        // Clear any lingering messages
        for _ in 0..MAX_RECV_RETRIES {
            if recv_message(&mut handle, UsbTimeout::from_millis(1)).is_err() {
                break;
            }
        }

        Ok(Self {
            device,
            timeout,
            handle: Mutex::new(handle),
        })
    }

    /// Borrow the `Device` for this connection
    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl Connection for UsbConnection {
    /// Send a command to the YubiHSM and read its response
    fn send_message(&self, _uuid: Uuid, cmd: Message) -> Result<Message, connector::Error> {
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
    handle: &mut rusb::DeviceHandle<rusb::Context>,
    data: &[u8],
    timeout: UsbTimeout,
) -> Result<usize, connector::Error> {
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
    handle: &mut rusb::DeviceHandle<rusb::Context>,
    timeout: UsbTimeout,
) -> Result<Message, connector::Error> {
    // Allocate a buffer which is the maximum size we expect to receive
    let mut response = vec![0u8; MAX_MSG_SIZE];

    for attempts_remaining in (0..MAX_RECV_RETRIES).rev() {
        match handle.read_bulk(YUBIHSM2_BULK_IN_ENDPOINT, &mut response, timeout.duration()) {
            Ok(nbytes) => {
                response.truncate(nbytes);
                return Ok(response.into());
            }
            // Sometimes I/O errors occur sporadically. When this happens,
            // retry the read for `MAX_RECV_RETRIES` attempts
            Err(rusb::Error::Io) => {
                debug!(
                    "I/O error during USB bulk message receive, retrying ({} attempts remaining)",
                    attempts_remaining
                );
            }
            // All other errors we return immediately
            Err(err) => return Err(err.into()),
        }
    }

    fail!(UsbError, "irrecoverable I/O error receiving bulk message")
}
