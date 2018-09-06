//! Status responses from `yubihsm-connector` process (from the YubiHSM2 SDK)

use std::str::FromStr;

use adapters::{AdapterError, AdapterErrorKind::ResponseError};
use serial::SerialNumber;

/// `yubihsm-connector` status message when healthy
const CONNECTOR_STATUS_OK: &str = "OK";

/// Status response from `yubihsm-connector` containing information about its
/// health and what `YubiHSM2` we're connected to
#[derive(Clone, Debug)]
pub struct ConnectorStatus {
    /// Status message for `yubihsm-connector` e.g. "OK"
    pub message: String,

    /// Serial number of `YubiHSM2` device. Only available if `yubihsm-connector`
    /// has been started with the --serial option
    pub serial: Option<SerialNumber>,

    /// `YubiHSM2` SDK version for `yubihsm-connector`
    pub version: String,

    /// PID of `yubihsm-connector`
    pub pid: u32,
}

impl ConnectorStatus {
    /// Parse the `yubihsm-connector` status response into a status struct
    pub fn parse(response_body: &str) -> Result<Self, AdapterError> {
        let mut response_message: Option<&str> = None;
        let mut response_serial: Option<&str> = None;
        let mut response_version: Option<&str> = None;
        let mut response_pid: Option<&str> = None;

        for line in response_body.split('\n') {
            if line.is_empty() {
                continue;
            }

            let mut fields = line.split('=');

            let key = fields
                .next()
                .ok_or_else(|| err!(ResponseError, "couldn't parse key"))?;

            let value = fields
                .next()
                .ok_or_else(|| err!(ResponseError, "couldn't parse value"))?;

            if let Some(remaining) = fields.next() {
                fail!(ResponseError, "unexpected additional data: {}", remaining)
            }

            match key {
                "status" => response_message = Some(value),
                "serial" => response_serial = Some(value),
                "version" => response_version = Some(value),
                "pid" => response_pid = Some(value),
                _ => (),
            }
        }

        let message = response_message
            .ok_or_else(|| err!(ResponseError, "missing status"))?
            .to_owned();

        let serial = match response_serial {
            Some("*") => None,
            Some(s) => Some(SerialNumber::from_str(s)?),
            None => fail!(ResponseError, "missing serial"),
        };

        let version = response_version
            .ok_or_else(|| err!(ResponseError, "missing version"))?
            .to_owned();

        let pid = response_pid
            .ok_or_else(|| err!(ResponseError, "missing PID"))?
            .parse()
            .map_err(|_| err!(ResponseError, "invalid PID: {}", response_pid.unwrap()))?;

        Ok(Self {
            message,
            serial,
            version,
            pid,
        })
    }

    /// Is the status message "OK"?
    pub fn is_ok(&self) -> bool {
        if self.message == CONNECTOR_STATUS_OK {
            true
        } else {
            debug!(
                "bad status message from yubihsm-connector: {}",
                &self.message
            );
            false
        }
    }
}
