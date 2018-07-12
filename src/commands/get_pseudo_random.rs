//! Get Pseudo Random Bytes
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html>
//!
use super::{Command, Response};
use {CommandType, Connector, Session, SessionError};

pub(crate) const MAX_RAND_BYTES: u16 = 2048 // packet size
    - 1 // response type byte
    - 2; // length of response data

/// Get some number of bytes of pseudo random data generated on the device
pub fn get_pseudo_random<C: Connector>(
    session: &mut Session<C>,
    bytes: u16,
) -> Result<Vec<u8>, SessionError> {
    if bytes >= MAX_RAND_BYTES {
        command_fail!(
            ProtocolError,
            "Requested too many random bytes (>= 2045) to fit in response packet"
        );
    }
    session
        .send_encrypted_command(GetPseudoRandomCommand { bytes })
        .map(|response| response.bytes)
}

/// Request parameters for `commands::get_pseudo_random`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPseudoRandomCommand {
    /// Number of random bytes to return
    pub bytes: u16,
}

impl Command for GetPseudoRandomCommand {
    type ResponseType = GetPseudoRandomResponse;
}

/// Response from `commands::get_pseudo_random`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetPseudoRandomResponse {
    /// Bytes of pseudo random data returned from the YubiHSM
    pub bytes: Vec<u8>,
}

impl Response for GetPseudoRandomResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetPseudoRandom;
}
