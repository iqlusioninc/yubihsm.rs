//! Initial YubiHSM 2 setup functionality using declarative device profiles.

mod error;
mod profile;
pub mod report;
mod role;

pub use self::{
    error::{Error, ErrorKind},
    profile::Profile,
    report::Report,
    role::Role,
};

use crate::{
    authentication::{self, Credentials, DEFAULT_AUTHENTICATION_KEY_ID},
    object, Capability, Client, Connector, Domain,
};
use anomaly::format_err;

/// Label to place on the temporary setup auth key ID
const SETUP_KEY_LABEL: &str = "yubihsm.rs temporary setup key";

/// Erase and reset an HSM device, then reinitialize it with the given
/// profile.
pub fn erase_device_and_init_with_profile(
    connector: Connector,
    credentials: Credentials,
    profile: Profile,
) -> Result<Report, Error> {
    // Reset the device
    let mut client = Client::open(connector, credentials, false)?;
    client.reset_device_and_reconnect(profile.reset_device_timeout)?;
    init_with_profile(client, profile)
}

/// Initialize an HSM device with the given profile.
///
/// This approach does not erase the device first, but generally assumes
/// the HSM is in a clean state.
///
/// The recommended approach is to use `erase_device_and_init_with_profile`
pub fn init_with_profile(client: Client, profile: Profile) -> Result<Report, Error> {
    let setup_auth_key_id = profile
        .setup_auth_key_id
        .ok_or_else(|| format_err!(ErrorKind::SetupFailed, "profile setup_auth_key_id unset!"))?;

    let temp_auth_key = authentication::Key::random();

    client
        .put_authentication_key(
            setup_auth_key_id,
            SETUP_KEY_LABEL.into(),
            Domain::all(),
            Capability::all(),
            Capability::all(),
            authentication::Algorithm::YubicoAes,
            temp_auth_key.clone(),
        )
        .map_err(|e| {
            format_err!(
                ErrorKind::SetupFailed,
                "error putting authentication key: {}",
                e
            )
        })?;

    info!(
        "installed temporary setup authentication key into slot {}",
        setup_auth_key_id
    );

    let connector = client.connector().clone();

    // Create a new client, connecting with the temporary auth key
    let client = Client::open(
        connector,
        Credentials::new(setup_auth_key_id, temp_auth_key),
        false,
    )
    .map_err(|e| {
        format_err!(
            ErrorKind::SetupFailed,
            "error reconnecting to HSM with setup auth key: {}",
            e
        )
    })?;

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
                ErrorKind::SetupFailed,
                "error deleting default authentication key from slot {}: {}",
                DEFAULT_AUTHENTICATION_KEY_ID,
                e
            )
        })?;

    let report = profile.provision(&client)?;

    if profile.delete_setup_auth_key {
        warn!(
            "deleting temporary setup authentication key from slot {}",
            setup_auth_key_id
        );
        client
            .delete_object(setup_auth_key_id, object::Type::AuthenticationKey)
            .map_err(|e| {
                format_err!(
                    ErrorKind::SetupFailed,
                    "error deleting temporary setup authentication key from slot {}: {}",
                    setup_auth_key_id,
                    e
                )
            })?;
    }

    Ok(report)
}
