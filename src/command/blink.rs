//! Blink the LED on the `YubiHSM2` for the given number of seconds
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>

use super::{Command, CommandType, Response};
use adapter::Adapter;
use client::{Client, SessionError};

/// Blink the YubiHSM2's LEDs (to identify it) for the given number of seconds
pub fn blink<A: Adapter>(session: &mut Client<A>, num_seconds: u8) -> Result<(), SessionError> {
    session.send_command(BlinkCommand { num_seconds })?;
    Ok(())
}

/// Request parameters for `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkCommand {
    /// Number of seconds to blink for
    pub num_seconds: u8,
}

impl Command for BlinkCommand {
    type ResponseType = BlinkResponse;
}

/// Response from `command::blink`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkResponse {}

impl Response for BlinkResponse {
    const COMMAND_TYPE: CommandType = CommandType::Blink;
}
