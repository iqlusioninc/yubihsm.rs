//! Roles for interacting with the YubiHSM 2

use super::{Error, ErrorKind};
use crate::Client;
pub use crate::{object, Capability, Credentials, Domain};
use anomaly::format_err;

/// Roles represent accounts on the device with specific permissions
#[derive(Clone, Debug)]
pub struct Role {
    /// Label to place on the authentication key for this role
    pub(super) authentication_key_label: object::Label,

    /// Credentials (auth key and ID) used to authenticate with this role
    pub(super) credentials: Credentials,

    /// Permissions for this role
    pub(super) capabilities: Capability,

    /// Set of permissions allowed to be set by objects created by this role
    pub(super) delegated_capabilities: Capability,

    /// Domains (logical partitions in the YubiHSM 2) this role has access to
    pub(super) domains: Domain,
}

impl Role {
    /// Create a new role object
    pub fn new(credentials: Credentials) -> Self {
        Self {
            authentication_key_label: Default::default(),
            credentials,
            capabilities: Capability::empty(),
            delegated_capabilities: Capability::empty(),
            domains: Domain::empty(),
        }
    }

    /// Set the label for this role's authentication key
    pub fn authentication_key_label<L>(mut self, label: L) -> Self
    where
        L: Into<object::Label>,
    {
        self.authentication_key_label = label.into();
        self
    }

    /// Set the capabilities (i.e. permission) for this role
    pub fn capabilities(mut self, capabilities: Capability) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the delegated capabilities for this role
    pub fn delegated_capabilities(mut self, capabilities: Capability) -> Self {
        self.delegated_capabilities = capabilities;
        self
    }

    /// Set the domains this role is allowed to access
    pub fn domains(mut self, domains: Domain) -> Self {
        self.domains = domains;
        self
    }

    /// Create this role within the YubiHSM 2 device
    pub fn create(&self, client: &Client) -> Result<(), Error> {
        client
            .put_authentication_key(
                self.credentials.authentication_key_id,
                self.authentication_key_label.clone(),
                self.domains,
                self.capabilities,
                self.delegated_capabilities,
                Default::default(),
                self.credentials.authentication_key.clone(),
            )
            .map_err(|e| format_err!(ErrorKind::SetupFailed, "error creating role: {}", e))?;

        Ok(())
    }
}
