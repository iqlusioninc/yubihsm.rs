//! Initial YubiHSM 2 setup functionality using declarative device profiles.

mod profile;
pub mod report;
mod role;

pub use self::{profile::Profile, report::Report, role::Role};

use crate::{
    authentication::{self, Credentials, DEFAULT_AUTHENTICATION_KEY_ID},
    object, Capability, Client, Connector, Domain,
};
use failure::Error;
use std::{
    thread,
    time::{Duration, SystemTime},
};

/// How long to initially wait for a device reset to complete
const DEVICE_RESET_WAIT_MS: u64 = 1000;

/// How frequently to poll the device in milliseconds after it's been reset
const DEVICE_POLL_INTERVAL_MS: u64 = 250;

/// Should we enable device reconnect during reset?
/// Disabled to ensure that reconnecting doesn't gloss over anything important
const ENABLE_RECONNECT_DURING_RESET: bool = false;

/// Label to place on the temporary setup auth key ID
const SETUP_KEY_LABEL: &str = "yubihsm.rs temporary setup key";

/// Erase and reset an HSM device, then reinitialize it with the given
/// profile.
pub fn erase_device_and_init_with_profile(
    connector: Connector,
    credentials: Credentials,
    profile: Profile,
) -> Result<Report, Error> {
    let setup_auth_key_id = profile.setup_auth_key_id.ok_or_else(|| {
        format_err!(
            "profile setup_auth_key_id must be set when using erase_device_and_init_with_profile"
        )
    })?;

    let temp_auth_key = authentication::Key::random();

    // Reset the device and use the new session with default credentials
    // to install the temporary setup authentication key
    perform_device_reset(connector.clone(), credentials, profile.reset_device_timeout)?
        .put_authentication_key(
            setup_auth_key_id,
            SETUP_KEY_LABEL.into(),
            Domain::all(),
            Capability::all(),
            Capability::all(),
            authentication::Algorithm::YUBICO_AES,
            temp_auth_key.clone(),
        )?;

    info!(
        "installed temporary setup authentication key into slot {}",
        setup_auth_key_id
    );

    let mut client = Client::open(
        connector,
        Credentials::new(setup_auth_key_id, temp_auth_key),
        ENABLE_RECONNECT_DURING_RESET,
    )
    .map_err(|e| format_err!("error reconnecting to HSM with setup auth key: {}", e))?;

    warn!(
        "deleting default authentication key from slot {}",
        DEFAULT_AUTHENTICATION_KEY_ID
    );

    client
        .delete_object(
            DEFAULT_AUTHENTICATION_KEY_ID,
            object::Type::AuthenticationKey,
        )
        .map_err(|e| {
            format_err!(
                "error deleting default authentication key from slot {}: {}",
                DEFAULT_AUTHENTICATION_KEY_ID,
                e
            )
        })?;

    let report = profile.provision(&mut client)?;

    if profile.delete_setup_auth_key {
        warn!(
            "deleting temporary setup authentication key from slot {}",
            setup_auth_key_id
        );
        client
            .delete_object(setup_auth_key_id, object::Type::AuthenticationKey)
            .map_err(|e| {
                format_err!(
                    "error deleting temporary setup authentication key from slot {}: {}",
                    setup_auth_key_id,
                    e
                )
            })?;
    }

    Ok(report)
}

/// Perform the device reset
fn perform_device_reset(
    connector: Connector,
    credentials: Credentials,
    timeout: Duration,
) -> Result<Client, Error> {
    // Warn people and give them a brief grace period to avoid oblitering their HSM
    warn!("factory resetting HSM device! all data will be lost!");
    thread::sleep(Duration::from_millis(DEVICE_RESET_WAIT_MS));

    // Reset the device
    Client::open(connector.clone(), credentials, false)?.reset_device()?;

    let deadline = SystemTime::now() + timeout;

    info!("waiting for device reset to complete");
    thread::sleep(Duration::from_millis(DEVICE_RESET_WAIT_MS));

    // Attempt to reconnect to the device with the default credentials
    loop {
        match Client::open(
            connector.clone(),
            Credentials::default(),
            ENABLE_RECONNECT_DURING_RESET,
        ) {
            Ok(client) => {
                debug!("successfully reconnected to HSM after reset!");
                return Ok(client);
            }
            Err(e) => {
                // If we're past the deadline, return an error
                if SystemTime::now() >= deadline {
                    bail!(
                        "timed out after {} seconds connecting to HSM after reset: {}",
                        timeout.as_secs(),
                        e
                    )
                } else {
                    debug!("error reconnecting to HSM: {}", e);
                    thread::sleep(Duration::from_millis(DEVICE_POLL_INTERVAL_MS))
                }
            }
        }
    }
}
