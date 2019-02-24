//! YubiHSM2 provisioning reports which record the server where the HSM was
//! provisioned, the username which performed the provisioning operation,
//! and the date provisioning occurred.

#![allow(clippy::new_without_default)]

use crate::{object, Capability, Client, Domain, OpaqueAlg, Uuid};
use chrono::{DateTime, Utc};
use failure::Error;
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
    pub fn new() -> Self {
        // TODO: handle these better on operating systems other than *IX
        Report {
            version: Version::default(),
            uuid: Uuid::new_v4(),
            username: env::var("LOGNAME").map(|u| u.to_owned()).ok(),
            hostname: env::var("HOSTNAME").map(|h| h.to_owned()).ok(),
            date: Utc::now(),
            software: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        }
    }

    /// Serialize a report as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Store this report in the YubiHSM at the given object ID
    pub fn store(&self, client: &mut Client, report_object_id: object::Id) -> Result<(), Error> {
        client
            .put_opaque(
                report_object_id,
                object::Label::from(REPORT_OBJECT_LABEL),
                Domain::all(),
                Capability::GET_OPAQUE,
                OpaqueAlg::DATA,
                self.to_json(),
            )
            .map_err(|e| format_err!("{}", e))?;

        Ok(())
    }
}

impl FromStr for Report {
    type Err = Error;

    /// Parse a `yubihsm::setup::Report` from its JSON serialization
    fn from_str(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s)
            .map_err(|e| format_err!("error parsing yubihsm::setup::Report JSON: {}", e))
    }
}
