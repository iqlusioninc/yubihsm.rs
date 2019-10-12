//! Device provisioning profiles: all attributes required to initialize a device

use super::{role::Role, Error, Report};
use crate::{object, wrap, AuditOption, Client};
use std::time::Duration;

/// Temporary account key to use for device provisioning.
/// Uses key ID #65534 as 65535 is reserved for internal use.
pub const DEFAULT_SETUP_KEY_ID: object::Id = 0xFFFE;

/// Object ID to write reports into after provisioning is complete
/// Uses key ID #65534 as 65535 is reserved for internal use.
pub const DEFAULT_REPORT_OBJECT_ID: object::Id = 0xFFFE;

/// YubiHSM 2 provisioning profile: a declarative profile specifying how a
/// device should be (re)provisioned.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Key ID to use for provisioning the device
    pub(super) setup_auth_key_id: Option<object::Id>,

    /// Should the setup auth key be deleted when provisioning is complete?
    pub(super) delete_setup_auth_key: bool,

    /// Auditing mode to configure the device with.
    pub(super) audit_option: AuditOption,

    /// Set of roles to create on the new device. These roles are accounts with
    /// unique credentials and different capabilities/domain access.
    pub(super) roles: Vec<Role>,

    /// Set of wrap keys to provision the device with. These keys are used
    /// for making encrypted backups of keys within the HSM, so they can be
    /// imported into other devices.
    pub(super) wrap_keys: Vec<wrap::Key>,

    /// Store a JSON copy of the provisioning report in the given opaque
    /// object slot
    pub(super) report_object_id: Option<object::Id>,

    /// How long to wait for the device to reset before giving up
    pub(super) reset_device_timeout: Duration,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            setup_auth_key_id: Some(DEFAULT_SETUP_KEY_ID),
            delete_setup_auth_key: true,
            audit_option: AuditOption::Off,
            roles: Vec::new(),
            wrap_keys: Vec::new(),
            report_object_id: Some(DEFAULT_REPORT_OBJECT_ID),
            reset_device_timeout: Duration::from_secs(10),
        }
    }
}

impl Profile {
    /// Create a new empty profile
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the auth key ID to use when performing device setup
    pub fn setup_auth_key_id(mut self, key_id: Option<object::Id>) -> Self {
        self.setup_auth_key_id = key_id;
        self
    }

    /// Enable mandatory consumption of the audit log. See:
    ///
    /// <https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.set_force_audit_option>
    pub fn audit_option(mut self, value: AuditOption) -> Self {
        self.audit_option = value;
        self
    }

    /// Set the initial roles to provision
    pub fn roles<I>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = Role>,
    {
        self.roles = roles.into_iter().collect();
        self
    }

    /// Set the wrap keys to initially provision
    pub fn wrap_keys<I>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = wrap::Key>,
    {
        self.wrap_keys = keys.into_iter().collect();
        self
    }

    /// Use this profile to provision the YubiHSM 2 with the given client
    pub fn provision(&self, client: &Client) -> Result<Report, Error> {
        for role in &self.roles {
            info!("installing role: {}", role.authentication_key_label);
            role.create(client)?;
        }

        for wrap_key in &self.wrap_keys {
            info!("installing wrap key: {}", &wrap_key.import_params.label);
            wrap_key.create(client)?;
        }

        if self.audit_option != AuditOption::Off {
            info!("setting force audit to: {:?}", self.audit_option);
            client.set_force_audit_option(self.audit_option)?;
        }

        let report = Report::new(client.device_info()?.serial_number);

        if let Some(report_object_id) = self.report_object_id {
            info!(
                "storing provisioning report in opaque object 0x{:x}",
                report_object_id
            );
            report.store(client, report_object_id)?;
        }

        Ok(report)
    }
}
