//! YubiHSM 2 provisioning reports which record the server where the HSM was
//! provisioned, the username which performed the provisioning operation,
//! and the date provisioning occurred.

use super::{Error, ErrorKind};
use crate::{
    device::SerialNumber,
    object, opaque,
    uuid::{self, Uuid},
    Capability, Client, Domain,
};
use anomaly::format_err;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{env, str::FromStr};

/// Label string for the provisioning report object
pub const REPORT_OBJECT_LABEL: &str = "yubihsm.rs setup report";

/// Report versions
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Version(usize);

impl From<Version> for usize {
    fn from(version: Version) -> usize {
        version.0
    }
}

/// YubiHSM provisioning report
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Report {
    /// Version of the report
    pub version: Version,

    /// UUID which uniquely identifies this provisioning report
    pub uuid: Uuid,

    /// Serial number of the HSM which was provisioned
    pub device_serial_number: String,

    /// Hostname the device was provisioned on
    pub hostname: Option<String>,

    /// Username of who provisioned the device
    pub username: Option<String>,

    /// Date the device was provisioned
    pub date: DateTime<Utc>,

    /// Software that performed the provisioning
    pub software: String,
}

impl Report {
    /// Make a new `yubihsm::setup::Report` from the ambient environment state
    pub fn new(serial_number: SerialNumber) -> Self {
        // TODO: handle these better on operating systems other than *IX
        Report {
            version: Version(1),
            uuid: uuid::new_v4(),
            device_serial_number: serial_number.to_string(),
            username: env::var("LOGNAME").ok(),
            hostname: env::var("HOSTNAME").ok(),
            date: Utc::now(),
            software: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        }
    }

    /// Serialize a report as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Store this report in the YubiHSM at the given object ID
    pub fn store(&self, client: &Client, report_object_id: object::Id) -> Result<(), Error> {
        client
            .put_opaque(
                report_object_id,
                object::Label::from(REPORT_OBJECT_LABEL),
                Domain::all(),
                Capability::GET_OPAQUE,
                opaque::Algorithm::Data,
                self.to_json(),
            )
            .map_err(|e| format_err!(ErrorKind::ReportFailed, "{}", e))?;

        Ok(())
    }
}

impl FromStr for Report {
    type Err = Error;

    /// Parse a `yubihsm::setup::Report` from its JSON serialization
    fn from_str(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(|e| {
            format_err!(
                ErrorKind::ReportFailed,
                "error parsing yubihsm::setup::Report JSON: {}",
                e
            )
            .into()
        })
    }
}
